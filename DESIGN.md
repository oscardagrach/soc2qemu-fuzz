# soc2qemu-fuzz design sketch

Fuzz firmware on SoCs ported with [soc2qemu](https://github.com/oscardagrach/soc2qemu), using
libafl_qemu in full-system mode. soc2qemu does the port; this project turns a port plus its
`fuzz/profile.yaml` into a running fuzzer.

Status: milestone 1 done; the rest is a sketch. Facts about LibAFL below were checked against LibAFL 0.16.1 (and `main`) on 2026-10-18;
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

1. **Done (2026-10-18).** Buffer-mode fuzzing on mps2-an385 (`selftest.sh`): soc2qemu's
   `selftest-m3-libafl` port + `targets/selftest-m3-buffer` (planted "SOC!" bug). The bug is
   found in about 13 s / ~100k executions at ~7.4k exec/s on one core. A buffer-mode target
   is used instead of soc2qemu's own fixture because that one has no input to fuzz.
2. MMIO mode on the same fixture: fuzz the `i2s +0x4` register the fixture polls.
3. A real Cortex-M port, then a Cortex-A port (`aarch64` feature).

## Implementation notes (milestone 1)

- One generic fuzzer (`fuzzer/`) driven by a generated `harness.toml`, rather than generated
  Rust per SoC. One build per QEMU tree and architecture (`target/<tree>-<arch>/`).
- libafl_qemu builds QEMU in `<LIBAFL_QEMU_DIR>/build`; soc2qemu builds libafl-based ports in
  `build-kit/` so the two don't collide.
- libafl_qemu forces `--enable-fdt=internal` and takes no extra configure flags. QEMU 10.2's
  bundled dtc and one unit test fail under GCC 16 `-Werror`, so `fuzz.sh` sets CC/CXX to
  `tools/cc-compat`, which downgrades exactly those two warnings.
- Crash = any stop other than the end breakpoint (crash handlers are breakpoints too).
  Timed runs must SIGINT only the broker: killing QEMU mid-input records a bogus crash.
  The broker leaves its client running after SIGINT, so `fuzz.sh` SIGKILLs the session.
- Crash dedup: the harness writes a signature hash to a `ValueObserver`, and the objective is
  `(Crash or Timeout) and NewHashFeedback`, so only unseen signatures are saved. Cortex-M
  signature = stacked PC (exception frame at SP+24, read through the CPU so the System Control
  Space is visible) + CFSR. Faults taken on PSP only get the CFSR, because libafl_qemu 0.16.1
  doesn't expose PSP. The seen-set lives in each client's state, so with several cores each
  client saves its own first copy. Fast snapshot restore resets CFSR between inputs.
  `--triage` applies the same signature by replay.

## Next

- Cortex-A signatures (ELR/ESR) with the Cortex-A milestone; PSP for Cortex-M RTOS faults.
- Crash minimization (saved inputs are whatever the mutator produced, e.g. 59-72 bytes for a
  4-byte trigger).

## Open questions

- MMIO read hooks in libafl_qemu full-system mode (see above).
- Cortex-A with a firmware chain: snapshot after DDR init and the MMU is on; TrustZone/EL3 state
  in snapshots.
- Keeping `QEMU_LIBAFL_REF` in soc2qemu in step with the LibAFL release this project pins.
