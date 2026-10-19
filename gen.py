#!/usr/bin/env -S uv run --script
# SPDX-License-Identifier: GPL-3.0-only
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml", "pyelftools"]
# ///
"""Generate a buffer-mode harness from a soc2qemu fuzz profile and a firmware ELF.

    ./gen.py <profile.yaml> --elf <firmware.elf> [-o harnesses/<name>]
             [--start SYM|ADDR] [--end SYM|ADDR] [--input SYM|ADDR] [--input-len N]
             [--crash SYM|ADDR ...] [--timeout-ms N]

Writes <out>/harness.toml (read by the fuzzer at runtime), <out>/corpus/seed, and
<out>/dummy.qcow2 (scratch drive QEMU needs for snapshots, created with the kit's qemu-img).

Values come from, in order: command line, profile `targets`, conventional symbol names
(start: main; end: fuzz_end, BREAKPOINT; input: FUZZ_INPUT; crash: fault_handler,
HardFault_Handler). Symbols resolve through the ELF symbol table; Thumb bit 0 is cleared
for 32-bit Arm functions so breakpoints land on the instruction.
"""
import argparse
import subprocess
import sys
from pathlib import Path

import yaml
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent
DEFAULTS = {
    "start": ["main"],
    "end": ["fuzz_end", "BREAKPOINT"],
    "input": ["FUZZ_INPUT"],
    "crash": ["fault_handler", "HardFault_Handler"],
}


def die(msg: str):
    sys.exit(f"error: {msg}")


class Symbols:
    def __init__(self, path: Path):
        self.path = path
        with open(path, "rb") as f:
            elf = ELFFile(f)
            self.machine = elf["e_machine"]
            self.syms = {}
            tab = elf.get_section_by_name(".symtab")
            if tab is None:
                die(f"{path} has no symbol table; pass addresses instead of names")
            for s in tab.iter_symbols():
                if s.name and s["st_value"]:
                    self.syms[s.name] = (s["st_value"], s["st_size"], s["st_info"]["type"])

    def addr(self, name: str) -> int:
        value, _, kind = self.syms[name]
        if self.machine == "EM_ARM" and kind == "STT_FUNC":
            value &= ~1
        return value

    def size(self, name: str) -> int:
        return self.syms[name][1]


def resolve(spec, syms: Symbols, what: str):
    """spec: CLI/profile value (symbol name or int/hex string) or None -> (addr, name)."""
    candidates = [spec] if spec not in (None, "") else DEFAULTS[what]
    for c in candidates:
        if isinstance(c, int):
            return c, None
        if isinstance(c, str) and c.lower().startswith("0x"):
            return int(c, 16), None
        if c in syms.syms:
            return syms.addr(c), c
    die(f"no {what} point: tried {candidates} in {syms.path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("profile", type=Path)
    ap.add_argument("--elf", type=Path, required=True)
    ap.add_argument("-o", dest="out", type=Path)
    ap.add_argument("--start")
    ap.add_argument("--end")
    ap.add_argument("--input")
    ap.add_argument("--input-len", type=int)
    ap.add_argument("--crash", action="append")
    ap.add_argument("--timeout-ms", type=int, default=1000)
    a = ap.parse_args()

    prof = yaml.safe_load(a.profile.read_text())
    if prof.get("schema") != "soc2qemu-fuzz-profile/1":
        die(f"unsupported profile schema {prof.get('schema')!r}")
    q = prof["qemu"]
    if not q.get("libafl_compatible"):
        die(f"{prof['soc']} is on the {q.get('base')} QEMU base; libafl_qemu needs a port started "
            "with `scripts/new-soc.sh <soc> --base libafl` in soc2qemu")
    tree = Path(q["tree"])
    if not (tree / "VERSION").exists():
        die(f"QEMU tree {tree} not found")

    syms = Symbols(a.elf.resolve())
    t = prof.get("targets") or {}
    start, start_sym = resolve(a.start or t.get("start_pc"), syms, "start")
    end, end_sym = resolve(a.end or t.get("end_pc"), syms, "end")
    inp, inp_sym = resolve(a.input or t.get("input_buffer"), syms, "input")
    crash_specs = a.crash or t.get("crash_pcs") or []
    crashes = []
    for c in crash_specs or DEFAULTS["crash"]:
        try:
            crashes.append(resolve(c, syms, "crash")[0])
        except SystemExit:
            if crash_specs:
                raise
    input_len = a.input_len or t.get("input_max_len") or (syms.size(inp_sym) if inp_sym else 0)
    if not input_len:
        die("input length unknown: pass --input-len")

    # libafl_qemu feature / QEMU target follows the firmware: AArch64 ELF -> aarch64, else arm.
    arch = {"EM_AARCH64": "aarch64", "EM_ARM": "arm"}.get(syms.machine) or die(f"unsupported ELF machine {syms.machine}")

    name = prof["soc"] + "-" + a.elf.stem
    out = (a.out or ROOT / "harnesses" / name).resolve()
    (out / "corpus").mkdir(parents=True, exist_ok=True)
    (out / "corpus" / "seed").write_bytes(b"\0" * min(input_len, 16))

    qemu_img = next((p for p in (tree / "build-kit" / "qemu-img", tree / "build" / "qemu-img") if p.exists()), None)
    if qemu_img is None:
        die(f"no qemu-img in {tree}/build-kit; build the soc2qemu port first (scripts/build.sh {prof['soc']})")
    drive = out / "dummy.qcow2"
    if not drive.exists():
        subprocess.run([str(qemu_img), "create", "-q", "-f", "qcow2", str(drive), "32M"], check=True)

    # Boot args from the profile, minus anything the harness controls itself.
    skip_with_value = {"-kernel", "-serial", "-monitor", "-display", "-qmp", "-d", "-D", "-M", "-machine"}
    extra, args = [], list(q.get("args") or [])
    i = 0
    while i < len(args):
        if args[i] in skip_with_value:
            i += 2
            continue
        extra.append(args[i])
        i += 1
    if any("${" in x for x in extra):
        die(f"profile args still contain kit variables: {extra}")

    qemu_args = [f"qemu-system-{arch}", "-machine", q["machine"], "-kernel", str(syms.path),
                 "-monitor", "null", "-serial", "null", "-nographic", "-snapshot", "-S",
                 "-icount", "shift=auto,align=off,sleep=off",
                 "-drive", f"if=none,format=qcow2,file={drive}", *extra]

    def toml_list(xs):
        return "[" + ", ".join(f'"{x}"' if isinstance(x, str) else hex(x) for x in xs) + "]"

    (out / "harness.toml").write_text(f"""# Generated by soc2qemu-fuzz gen.py; regenerate rather than edit.
# profile: {a.profile.resolve()}
# elf:     {syms.path}
soc = "{prof['soc']}"
profile = "{prof.get('profile') or ''}"  # soc2qemu spec profile; "m" enables Cortex-M fault signatures
arch = "{arch}"
qemu_dir = "{tree}"
qemu_args = {toml_list(qemu_args)}

[target]
start = {hex(start)}        # {start_sym or 'address'}: snapshot point
end = {hex(end)}          # {end_sym or 'address'}: input fully processed
crashes = {toml_list(crashes)}
input = {hex(inp)}  # {inp_sym or 'address'}
input_max_len = {input_len}
timeout_ms = {a.timeout_ms}
""")
    print(f"{out}/harness.toml: {arch}, machine {q['machine']}, start {hex(start)}, end {hex(end)}, "
          f"crashes {[hex(c) for c in crashes]}, input {hex(inp)} ({input_len} bytes)")


if __name__ == "__main__":
    main()
