#!/usr/bin/env bash
# Acceptance check: fuzz the buffer-mode target on soc2qemu's selftest-m3-libafl port. Both
# planted bugs ("SOC!" UNDEFINSTR, "BAD!" INVSTATE) must be found, deduplicated to exactly one
# saved crash each, and confirmed by --triage; nothing else may be reported.
#   ./selftest.sh [path/to/soc2qemu] [seconds]
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
kit="${1:-$root/../qemu}"; secs="${2:-180}"
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

bin="$root/target/selftest-m3-libafl-arm/release/soc2qemu-fuzz"
fail=0
got="$(for f in "$h"/crashes/[0-9a-f]*; do [[ -e "$f" ]] && head -c4 "$f" && echo; done | sort | paste -sd' ')"
if [[ "$got" != "BAD! SOC!" ]]; then
  echo "FAIL: expected one 'BAD!' and one 'SOC!' crash, got [${got}] in ${secs}s (log: $h/selftest.log)"; fail=1
fi
rm -rf "$h/crashes-unique"
triage="$("$bin" "$h/harness.toml" --triage "$h/crashes")"
echo "$triage" | grep -q "^2 unique crash signature" || { echo "FAIL: triage:"; echo "$triage"; fail=1; }
echo "$triage" | grep -q "pc=0x.* (UNDEFINSTR)" && echo "$triage" | grep -q "pc=0x100 .* (INVSTATE)" ||
  { echo "FAIL: triage signatures:"; echo "$triage"; fail=1; }
grep -q panicked "$h/selftest.log" && { echo "FAIL: panic in fuzzer log"; fail=1; }
[[ $fail -eq 0 ]] && { echo "PASS: both bugs found in ${secs}s, one crash each, triage agrees"; echo "$triage" | sed 's/^/  /'; }
exit $fail
