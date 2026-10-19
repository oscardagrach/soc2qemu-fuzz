# soc2qemu-fuzz

Full-system fuzzing for SoCs ported with [soc2qemu](https://github.com/oscardagrach/soc2qemu),
built on [LibAFL](https://github.com/AFLplusplus/LibAFL)'s libafl_qemu (0.16.1).

**Status: early.** What works: Cortex-M firmware, fuzz input written to a RAM buffer
("buffer mode") or returned by a peripheral's registers ("MMIO mode"), crash deduplication and
triage. Not yet: Cortex-A, crash minimization. See [DESIGN.md](DESIGN.md) for the plan.

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
./gen.py ... --mmio [PERIPHERAL|ADDR:SIZE]                                # MMIO mode instead
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
MMIO mode (`--mmio`) feeds the input through one peripheral instead of a RAM buffer: every
read the firmware makes from that peripheral's registers returns the next input bytes, and
writes are ignored. `--mmio` alone picks the peripheral of the profile's top polled input
candidate (the register the firmware was stuck polling during bring-up). The run ends cleanly
when the firmware reads past the end of the input. This uses a small QEMU device,
`qemu/soc2qemu-fuzz-mmio.c`, which `fuzz.sh build` copies into the port's QEMU tree
(`hw/misc/`, plus one line in `hw/misc/meson.build`), so the port's worktree shows those two
changes. The device also needs 64 KB of unused physical address space for its input window
(`--mmio-buf`, default `0xf0000000`); `gen.py` and QEMU both refuse an address that's in use.

`--replay` shows one input's signature; `--triage <dir>` groups any directory of crashing
inputs by signature and copies the smallest of each to `crashes-unique/`.

## Self-test
`./selftest.sh [path/to/soc2qemu] [seconds]` fuzzes two targets on soc2qemu's
`selftest-m3-libafl` port (mps2-an385): `targets/selftest-m3-buffer` in buffer mode and
`targets/selftest-m3-mmio` in MMIO mode (input through the i2s registers it polls). It finds
soc2qemu next to this repo (`../soc2qemu` or `../qemu`) unless you pass a path, and runs each
mode for 180 s (buffer) or 360 s (MMIO) by default (`MODES=mmio` runs one); the first run also clones and builds QEMU.
Each target has two planted bugs with different fault types; a mode passes when each is saved
exactly once and `--triage` agrees. Timing varies from run to run, so a short run can miss one
bug.

## License

Dual-licensed under GPL-3.0-only or a commercial license; see [LICENSING.md](LICENSING.md).
A built fuzzer contains QEMU, so distributing binaries is also subject to QEMU's GPL.
Contributions require agreeing to the [CLA](CLA.md). Includes code adapted from LibAFL; see
[NOTICE](NOTICE).
