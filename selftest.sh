#!/usr/bin/env bash
# Milestone 1 acceptance check: fuzz the buffer-mode target on soc2qemu's selftest-m3-libafl
# port and confirm the planted bug is found, replays as a crash, and nothing else is reported.
#   ./selftest.sh [path/to/soc2qemu] [seconds]
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
kit="${1:-$root/../qemu}"; secs="${2:-60}"
profile="$kit/socs/selftest-m3-libafl/fuzz/profile.yaml"
h="$root/harnesses/selftest-m3-libafl-target"

[[ -f "$kit/worktrees/selftest-m3-libafl/build-kit/qemu-system-aarch64" ]] ||
  "$kit/scripts/new-soc.sh" selftest-m3-libafl --base libafl
"$kit/scripts/build.sh" selftest-m3-libafl >/dev/null
[[ -d "$kit/socs/selftest-m3-libafl/bringup/runs" ]] ||
  "$kit/scripts/bringup-run.py" selftest-m3-libafl --label selftest >/dev/null || true
"$kit/scripts/fuzz-profile.py" selftest-m3-libafl >/dev/null

make -s -C "$root/targets/selftest-m3-buffer"
"$root/gen.py" "$profile" --elf "$root/targets/selftest-m3-buffer/target.elf" -o "$h" >/dev/null
"$root/fuzz.sh" build "$h" >/dev/null
rm -rf "$h/crashes"
"$root/fuzz.sh" run "$h" "$secs" >"$h/selftest.log" 2>&1

bin="$(ls "$root"/target/selftest-m3-libafl-arm/release/soc2qemu-fuzz)"
fail=0; n=0
for f in "$h"/crashes/[0-9a-f]*; do
  [[ -e "$f" ]] || break
  n=$((n + 1))
  if [[ "$(head -c4 "$f")" != "SOC!" ]]; then echo "FAIL: unexpected crash input $(basename "$f")"; fail=1; fi
done
[[ $n -gt 0 ]] || { echo "FAIL: no crash found in ${secs}s (log: $h/selftest.log)"; exit 1; }
first="$(ls "$h"/crashes/[0-9a-f]* | head -1)"
"$bin" "$h/harness.toml" --replay "$first" | grep -q "crash (crash breakpoint)" ||
  { echo "FAIL: $first does not replay as a crash"; fail=1; }
grep -q panicked "$h/selftest.log" && { echo "FAIL: panic in fuzzer log"; fail=1; }
[[ $fail -eq 0 ]] && echo "PASS: $n crash(es) in ${secs}s, all 'SOC!', replay confirms crash"
exit $fail
