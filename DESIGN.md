# soc2qemu-fuzz design sketch

Fuzz firmware on SoCs ported with [soc2qemu](https://github.com/oscardagrach/soc2qemu), using
libafl_qemu in full-system mode. soc2qemu does the port; this project turns a port plus its
`fuzz/profile.yaml` into a running fuzzer.

Status: sketch. Facts about LibAFL below were checked against LibAFL `main` on 2026-10-18;
everything marked **open** is unverified.

## Inputs

- A soc2qemu port started with `scripts/new-soc.sh <soc> --base libafl`, so the QEMU tree is
  `qemu-libafl-bridge` at the commit libafl_qemu pins (`LIBAFL_QEMU_GIT_REV`, QEMU 10.2.0 today).
- `socs/<soc>/fuzz/profile.yaml` (schema `soc2qemu-fuzz-profile/1`): QEMU tree and boot
  arguments, address map, `input_candidates` (MMIO reads no model answered; `polled` ones
  first), `snapshot_candidates` (milestones reached, hot PCs), `baseline_log_messages`, and
  `targets` (start/end PC, input buffer), which firmware analysis fills in.
- The firmware image(s) and, when available, symbols.

## How libafl_qemu full-system fuzzing works (verified)

From `fuzzers/full_system/qemu_baremetal` (runs on `mps2-an385` with the `arm` + `systemmode`
features):

1. Build QEMU from a tree you provide: `LIBAFL_QEMU_DIR=<path>` (build.rs also supports
   cloning the pinned fork itself).
2. Configure the machine with `QemuConfig::builder()` (`machine`, `kernel`, `snapshot`, a
   qcow2 drive for snapshots, `start_cpu(false)`).
3. Run to a start breakpoint, take `create_fast_snapshot`, then per input:
   `write_phys_mem(input_addr, buf)`, run to the end breakpoint, restore the snapshot.
4. Any stop other than the end breakpoint is a crash. Coverage comes from the edges map.

## Harness generation

`soc2qemu-fuzz gen <profile.yaml>` produces a Rust crate per SoC:

- **QEMU config** from `profile.qemu` (`machine`, boot `args`), with `LIBAFL_QEMU_DIR` set to
  `profile.qemu.tree`. Refuse to run when `libafl_compatible` is false.
- **Start/end points** from `profile.targets`. When empty, propose them: the PC of the
  loop that reads the top `polled` input candidate (from `hot_pcs`) is usually just past the
  last good state, a good snapshot point. Confirming them is a firmware-analysis step (the
  soc2qemu `qemu-firmware-re` skill and Ghidra), not something to guess silently.
- **Input delivery**, two modes:
  - *Buffer mode* (verified pattern): the firmware reads input from a RAM buffer
    (`targets.input_buffer`), written with `write_phys_mem`. Fits parsers, protocol
    handlers, anything fed from a known buffer.
  - *MMIO mode*: feed fuzz bytes when firmware reads `input_candidates` registers (UART RX,
    SPI/I2C data, status registers). This is where soc2qemu's data is most useful.
    **Open:** whether libafl_qemu exposes MMIO read hooks in full-system mode. If not, add a
    small "fuzz-input" QEMU device to the libafl-based port: it replaces the unimplemented
    stub at a candidate address and serves bytes from a RAM window the harness fills with
    `write_phys_mem`. That keeps the harness on the verified API.
- **Crash oracle:** unexpected stops (fault handlers, `HardFault`/exception vectors, panic
  symbols), watchdog/reset requests, and new QEMU log messages that aren't in
  `baseline_log_messages`. Timeouts become hangs.

## Milestones

1. Fuzz soc2qemu's `selftest-m3` fixture in buffer mode. It's the same board as LibAFL's
   bare-metal example, so it isolates our generation logic from board problems.
2. MMIO mode on the same fixture: fuzz the `i2s +0x4` register the fixture polls.
3. A real Cortex-M port, then a Cortex-A port (`aarch64` feature).

## Open questions

- MMIO read hooks in libafl_qemu full-system mode (see above).
- Cortex-A with a firmware chain: snapshot after DDR init and the MMU is on; TrustZone/EL3 state
  in snapshots.
- Keeping `QEMU_LIBAFL_REF` in soc2qemu in step with the LibAFL release this project pins.
- License: decide before publishing (soc2qemu is GPL-3.0-only + commercial; LibAFL is
  Apache-2.0/MIT).
