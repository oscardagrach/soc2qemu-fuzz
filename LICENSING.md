# Licensing

Copyright (C) 2026 Ryan Grachek

This project is dual-licensed:

1. **GNU General Public License v3.0 only** (`GPL-3.0-only`), see [LICENSE](LICENSE).
   You may use, modify, and redistribute it under the GPL's terms. If you distribute it or
   a derivative work, you must do so under the GPL, including making the corresponding
   source available.

2. **Commercial license.** If you want to use, modify, or distribute this project's source
   under terms other than the GPL, contact Ryan Grachek (https://github.com/oscardagrach)
   for a commercial license.

## Scope

This license covers this repository: `gen.py`, `fuzz.sh`, `selftest.sh`, `tools/`,
`fuzzer/`, and `targets/`. Parts of `fuzzer/src/main.rs` are adapted from LibAFL, used under
its MIT license option; see [NOTICE](NOTICE).

It does not cover:

- **QEMU.** libafl_qemu compiles QEMU (mostly GPL-2.0-or-later) into the fuzzer binary, so
  anyone distributing a built fuzzer must follow QEMU's license for it, whichever license
  they hold for this project's source.
- **LibAFL and other Rust dependencies**, which keep their own licenses (see
  `fuzzer/Cargo.lock` for the exact set).
- **soc2qemu ports** the fuzzer is built against, and **firmware** you fuzz, which remain
  under their owners' terms.

## Contributions

Contributions are accepted only under the [Contributor License Agreement](CLA.md), which
lets the copyright holder continue to offer the project under both licenses.
