// SPDX-License-Identifier: GPL-3.0-only
// Builds QEMU from LIBAFL_QEMU_DIR (the soc2qemu port tree, set by fuzz.sh) via libafl_qemu_build.
fn main() {
    libafl_qemu_build::build_libafl_qemu();
}
