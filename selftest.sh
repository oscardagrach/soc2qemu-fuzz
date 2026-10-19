#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Acceptance check on soc2qemu's selftest-m3-libafl port, once per input mode: buffer
# (targets/selftest-m3-buffer) and mmio (targets/selftest-m3-mmio, input through the
# soc2qemu-fuzz-mmio device over i2s). In each, both planted bugs ("SOC!" UNDEFINSTR, "BAD!"
# INVSTATE) must be found, deduplicated to exactly one saved crash each, and confirmed by
# --triage; nothing else may be reported.
#   ./selftest.sh [path/to/soc2qemu] [seconds per mode]   (default: ../soc2qemu or ../qemu;
#                                                          180 s buffer, 360 s mmio)
#   MODES="mmio" ./selftest.sh ...                         (default: "buffer mmio")
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
secs_arg="${2:-}"
# soc2qemu checkout: the argument, else a sibling directory named soc2qemu (a GitHub clone) or qemu.
kit="${1:-}"
if [[ -z "$kit" ]]; then
  for d in "$root/../soc2qemu" "$root/../qemu"; do
    [[ -x "$d/scripts/new-soc.sh" ]] && { kit="$(cd "$d" && pwd)"; break; }
  done
fi
[[ -n "$kit" && -x "$kit/scripts/new-soc.sh" ]] ||
  { echo "usage: selftest.sh <path/to/soc2qemu> [seconds] (no soc2qemu checkout found next to this repo)" >&2; exit 2; }
profile="$kit/socs/selftest-m3-libafl/fuzz/profile.yaml"

[[ -f "$kit/worktrees/selftest-m3-libafl/build-kit/qemu-system-aarch64" ]] ||
  "$kit/scripts/new-soc.sh" selftest-m3-libafl --base libafl
"$kit/scripts/build.sh" selftest-m3-libafl >/dev/null
# soc2qemu's fixture is a build product (gitignored there); its profile needs one bring-up run.
make -s -C "$kit/tests/fixture-m3"
[[ -d "$kit/socs/selftest-m3-libafl/bringup/runs" ]] ||
  "$kit/scripts/bringup-run.py" selftest-m3-libafl --label selftest >/dev/null || true
"$kit/scripts/fuzz-profile.py" selftest-m3-libafl >/dev/null

bin="$root/target/selftest-m3-libafl-arm/release/soc2qemu-fuzz"
fail=0
check() {  # <mode> <gen.py args...>
  local mode="$1"; shift
  # MMIO mode is slower on this target: status polls and command bytes share one input stream,
  # so mutations that change the poll count shift the command. Measured: both bugs in 34-118 s
  # in 3 of 6 runs, one bug missed in the others at 120-180 s.
  local secs="${secs_arg:-$([[ $mode == mmio ]] && echo 360 || echo 180)}"
  local h="$root/harnesses/selftest-$mode"
  make -s -C "$root/targets/selftest-m3-$mode"
  "$root/gen.py" "$profile" --elf "$root/targets/selftest-m3-$mode/target.elf" -o "$h" "$@" >/dev/null
  "$root/fuzz.sh" build "$h" >/dev/null
  rm -rf "$h/crashes" "$h/crashes-unique"
  "$root/fuzz.sh" run "$h" "$secs" >"$h/selftest.log" 2>&1

  local n triage ok=1
  n=$(find "$h/crashes" -type f ! -name '.*' 2>/dev/null | wc -l)
  [[ $n -eq 2 ]] || { echo "FAIL [$mode]: expected 2 saved crashes, got $n in ${secs}s (log: $h/selftest.log)"; ok=0; }
  triage="$("$bin" "$h/harness.toml" --triage "$h/crashes" 2>/dev/null | grep -v '^\[')"
  echo "$triage" | grep -q "^2 unique crash signature" &&
    echo "$triage" | grep -q "pc=0x.* (UNDEFINSTR)" && echo "$triage" | grep -q "pc=0x100 .* (INVSTATE)" ||
    { echo "FAIL [$mode]: triage:"; echo "$triage"; ok=0; }
  grep -q panicked "$h/selftest.log" && { echo "FAIL [$mode]: panic in fuzzer log"; ok=0; }
  if [[ $ok -eq 1 ]]; then
    echo "PASS [$mode]: both bugs found in ${secs}s, one crash each, triage agrees"; echo "$triage" | sed 's/^/  /'
  else
    fail=1
  fi
}
for mode in ${MODES:-buffer mmio}; do
  case "$mode" in
    buffer) check buffer ;;
    mmio) check mmio --mmio i2s ;;
    *) echo "unknown mode $mode" >&2; exit 2 ;;
  esac
done
exit $fail
