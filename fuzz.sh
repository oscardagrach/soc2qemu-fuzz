#!/usr/bin/env bash
# Build the fuzzer against a harness's QEMU tree, or run it.
#   ./fuzz.sh build <harness-dir>
#   ./fuzz.sh run   <harness-dir> [seconds]    (default: until Ctrl-C; crashes land in <harness-dir>/crashes)
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cmd="${1:-}"; h="$(cd "${2:?harness dir}" && pwd)"
toml="$h/harness.toml"
[[ -f "$toml" ]] || { echo "no $toml (run gen.py first)" >&2; exit 2; }

field() { sed -n "s/^$1 = \"\(.*\)\"/\1/p" "$toml"; }
arch="$(field arch)"; qemu_dir="$(field qemu_dir)"
target_dir="$root/target/$(basename "$qemu_dir")-$arch"
bin="$target_dir/release/soc2qemu-fuzz"

case "$cmd" in
  build)
    # libafl_qemu configures and builds QEMU in $qemu_dir/build (soc2qemu builds in build-kit there).
    # CC/CXX: see tools/cc-compat (old QEMU + bundled dtc vs. a newer GCC under -Werror).
    LIBAFL_QEMU_DIR="$qemu_dir" CC="$root/tools/cc-compat" CXX="$root/tools/cxx-compat" \
      cargo build --release \
      --manifest-path "$root/fuzzer/Cargo.toml" --target-dir "$target_dir" \
      --no-default-features --features "$arch"
    echo "built $bin"
    ;;
  run)
    [[ -x "$bin" ]] || { echo "not built: ./fuzz.sh build $h" >&2; exit 2; }
    secs="${3:-}"
    cd "$h"
    if [[ -n "$secs" ]]; then
      # Own session, so everything this run spawned can be found afterwards. SIGINT goes to the
      # broker only: signalling the whole group kills QEMU mid-input and records a bogus crash.
      # The broker doesn't stop its clients on SIGINT, so SIGKILL whatever is left; SIGKILL
      # can't trigger LibAFL's crash handler.
      setsid "$bin" "$toml" &
      pid=$!
      sleep "$secs"
      kill -INT "$pid" 2>/dev/null || true
      for _ in $(seq 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
      kill -KILL -- "-$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    else
      "$bin" "$toml"
    fi
    n=$(find "$h/crashes" -type f ! -name '.*' 2>/dev/null | wc -l)
    echo "crashes: $n in $h/crashes"
    ;;
  *) echo "usage: fuzz.sh build|run <harness-dir> [seconds]" >&2; exit 2 ;;
esac
