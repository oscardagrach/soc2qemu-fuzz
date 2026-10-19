# soc2qemu-fuzz

Full-system fuzzing for SoCs ported with [soc2qemu](https://github.com/oscardagrach/soc2qemu),
built on [LibAFL](https://github.com/AFLplusplus/LibAFL)'s libafl_qemu (0.16.1).

Early stage: buffer-mode fuzzing works on Cortex-M; see [DESIGN.md](DESIGN.md) for the plan.

## Requirements
- A soc2qemu port started on the libafl base (`scripts/new-soc.sh <soc> --base libafl`),
  built, with at least one bring-up run, and its profile exported
  (`scripts/fuzz-profile.py <soc>`).
- Rust 1.93.1 or newer, clang/libclang, and the toolchain soc2qemu needs.
- A firmware ELF with symbols (or addresses on the command line).

## Use
```
./gen.py <soc2qemu>/socs/<soc>/fuzz/profile.yaml --elf firmware.elf     # -> harnesses/<soc>-<elf>/
./fuzz.sh build harnesses/<soc>-<elf>     # first build compiles QEMU from the port tree (~1 min)
./fuzz.sh run   harnesses/<soc>-<elf> [seconds]
target/<tree>-<arch>/release/soc2qemu-fuzz harnesses/<soc>-<elf>/harness.toml --replay <input>
target/<tree>-<arch>/release/soc2qemu-fuzz harnesses/<soc>-<elf>/harness.toml --triage <dir>
```

`gen.py` takes the snapshot point, end point, input buffer and crash handlers from the
profile's `targets`, from `--start/--end/--input/--crash`, or from conventional symbol names
(`main`, `fuzz_end`/`BREAKPOINT`, `FUZZ_INPUT`, `fault_handler`/`HardFault_Handler`).
Crashes are deduplicated while fuzzing: `harnesses/<name>/crashes/` gets the first input for
each crash signature. On Cortex-M the signature is the faulting PC from the exception frame
plus the fault status register (CFSR); elsewhere it's the PC where execution stopped.
`--replay` shows one input's signature; `--triage <dir>` groups any directory of crashing
inputs by signature and copies the smallest of each to `crashes-unique/`.

## Self-test
`./selftest.sh [path/to/soc2qemu] [seconds]` (default 180 s) fuzzes `targets/selftest-m3-buffer`
on soc2qemu's `selftest-m3-libafl` port (mps2-an385). It has two planted bugs with different
fault types; the check passes when each is saved exactly once and `--triage` agrees.
