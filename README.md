# soc2qemu-fuzz

Full-system fuzzing for SoCs ported with [soc2qemu](https://github.com/oscardagrach/soc2qemu),
built on [LibAFL](https://github.com/AFLplusplus/LibAFL)'s libafl_qemu (0.16.1).

**Status: early (v0.1).** What works: Cortex-M firmware, fuzz input written to a RAM buffer
("buffer mode"), crash deduplication and triage. Not yet: Cortex-A, feeding input through
peripheral registers ("MMIO mode"), crash minimization. See [DESIGN.md](DESIGN.md) for the
plan.

## Requirements
- A soc2qemu port started on the libafl base (`scripts/new-soc.sh <soc> --base libafl`),
  built, with at least one bring-up run, and its profile exported
  (`scripts/fuzz-profile.py <soc>`).
- Linux (libafl_qemu is Linux-only), Rust 1.93.1 or newer, clang/libclang, `uv`, and the
  toolchain soc2qemu needs.
- A firmware ELF with symbols (or addresses on the command line).
- For the self-test: `make` and `arm-none-eabi-gcc`.

## Use
```
./gen.py <soc2qemu>/socs/<soc>/fuzz/profile.yaml --elf firmware.elf     # -> harnesses/<soc>-<elf>/
./fuzz.sh build harnesses/<soc>-<elf>     # first build compiles QEMU from the port tree (~1 min)
./fuzz.sh run   harnesses/<soc>-<elf> [seconds]
target/<tree>-<arch>/release/soc2qemu-fuzz harnesses/<soc>-<elf>/harness.toml --replay <input>
target/<tree>-<arch>/release/soc2qemu-fuzz harnesses/<soc>-<elf>/harness.toml --triage <dir>
```

Environment: `CORES` (LibAFL core list, default `1`, e.g. `0-7`) and `BROKER_PORT` (default
1338; give each concurrently running fuzzer its own).

`gen.py` takes the snapshot point, end point, input buffer and crash handlers from the
profile's `targets`, from `--start/--end/--input/--crash`, or from conventional symbol names
(`main`, `fuzz_end`/`BREAKPOINT`, `FUZZ_INPUT`, `fault_handler`/`HardFault_Handler`).
Crashes are deduplicated while fuzzing: `harnesses/<name>/crashes/` gets the first input for
each crash signature. On Cortex-M the signature is the faulting PC from the exception frame
plus the fault status register (CFSR); elsewhere it's the PC where execution stopped.
`--replay` shows one input's signature; `--triage <dir>` groups any directory of crashing
inputs by signature and copies the smallest of each to `crashes-unique/`.

## Self-test
`./selftest.sh [path/to/soc2qemu] [seconds]` fuzzes `targets/selftest-m3-buffer` on soc2qemu's
`selftest-m3-libafl` port (mps2-an385). It finds soc2qemu next to this repo (`../soc2qemu` or
`../qemu`) unless you pass a path, and runs 180 s by default; the first run also clones and
builds QEMU. The target has two planted bugs with different fault types; the check passes
when each is saved exactly once and `--triage` agrees. Timing varies from run to run, so a
short run can miss one bug.

## License

Dual-licensed under GPL-3.0-only or a commercial license; see [LICENSING.md](LICENSING.md).
A built fuzzer contains QEMU, so distributing binaries is also subject to QEMU's GPL.
Contributions require agreeing to the [CLA](CLA.md). Includes code adapted from LibAFL; see
[NOTICE](NOTICE).
