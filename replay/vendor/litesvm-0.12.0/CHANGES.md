# Modifications to LiteSVM 0.12.0

This directory is a vendored copy of [LiteSVM](https://github.com/LiteSVM/litesvm)
version 0.12.0, licensed under Apache-2.0 (see LICENSE in this directory).

In accordance with Apache-2.0 section 4(b), the following changes were made to
the original source by Aaron Elijah Mars for the soldecomp replay runner:

- `src/lib.rs`: added `LiteSVM::set_instructions_sysvar_override(&mut self, data: Vec<u8>)`
  and a backing `instructions_sysvar_override` field, so an isolated CPI replay can
  receive the parent transaction's instructions sysvar bytes.
- `src/lib.rs`: added `LiteSVM::with_custom_syscall(...)` to register a custom
  syscall in both program runtime environments before the default programs are loaded.

No other files were modified. The original crate metadata is preserved in
`Cargo.toml.orig`. Upstream LiteSVM is unaffiliated with this project and does not
endorse these changes.
