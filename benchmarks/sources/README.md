# Source-built security controls

`authorization.rs` has a missing-signer variant and a checked variant. The idea follows [Coral's public signer authorization example](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/0-signer-authorization). `guarded_state.rs` has three minimal checks for stale oracle data, minimum output, and a borrow limit. `owner_check.rs` has a variant that uses a read-only account without checking its owner and a variant that requires the account to be System-owned, following the missing-owner-check pattern from [Coral's account data matching example](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/2-owner-checks). `tag_check.rs` has a variant that uses a program-owned account without checking its 8-byte type discriminator and a variant that requires the discriminator to match, following the account-type-cosplay pattern from [Coral's type cosplay example](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/3-type-cosplay). `cpi_check.rs` has a variant that trusts a caller-supplied program account and a variant that requires it to be the SPL Token program, following the arbitrary-CPI pattern from [Coral's arbitrary CPI example](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/5-arbitrary-cpi). All five are deliberately small synthetic programs. They are not deployed contracts or evidence of an exploited bug.

Build the pinned SBF files with Solana platform tools v1.48:

```sh
RUSTC=.toolchains/platform-tools-v1.48/rust/bin/rustc
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort benchmarks/sources/authorization.rs -o benchmarks/programs/auth-insecure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort --cfg secure benchmarks/sources/authorization.rs -o benchmarks/programs/auth-secure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort benchmarks/sources/guarded_state.rs -o benchmarks/programs/guarded-insecure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort --cfg secure benchmarks/sources/guarded_state.rs -o benchmarks/programs/guarded-secure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort benchmarks/sources/owner_check.rs -o benchmarks/programs/owner-insecure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort --cfg secure benchmarks/sources/owner_check.rs -o benchmarks/programs/owner-secure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort benchmarks/sources/tag_check.rs -o benchmarks/programs/tag-insecure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort --cfg secure benchmarks/sources/tag_check.rs -o benchmarks/programs/tag-secure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort benchmarks/sources/cpi_check.rs -o benchmarks/programs/cpi-insecure.so
$RUSTC --target sbf-solana-solana --crate-type cdylib -C opt-level=2 -C panic=abort --cfg secure benchmarks/sources/cpi_check.rs -o benchmarks/programs/cpi-secure.so
```

The manifest pins each ELF SHA-256. The auth check uses an independent fee payer, then executes one signed update followed by an unsigned update in the same LiteSVM. The guarded checks change the oracle timestamp, minimum output, or borrow amount and compare the vulnerable and fixed binaries. These controls verify the detector wiring. The benchmark reports real-world known-bug coverage separately; it is currently zero.

## Independently authored example

`benchmarks/programs/security-examples.so` comes from [Aypp23/solana-security-examples](https://github.com/Aypp23/solana-security-examples) at commit `e0870e93453100828140267d44252dbbe4c3f933`. It is Apache 2.0 licensed; the license is copied to `benchmarks/programs/SECURITY-EXAMPLES-LICENSE`. The ELF SHA-256 is `0c0c7bae750e0fcd579f0bf961822c6a40df3f65f17c5babd610a3abd2208a68`. Build from the unmodified upstream source with the Solana platform-tools v1.48 SBF compiler, host Cargo 1.99.1, and `cargo update -p blake3 --precise 1.8.2` in a temporary checkout. The dependency pin selects `constant_time_eq` 0.3.1, which works with the platform compiler. Then run `cargo build --release --target sbf-solana-solana` from its `security-examples` crate.

Example 1 tests a missing authority signer. Example 15 tests acceptance of a repeated instruction after a valid earlier transaction. Each has an insecure and fixed handler in the same ELF. The benchmark checks the vault balance after both local transactions, the nonce for replay protection, and the fixed handler's expected error. The example is deliberately vulnerable and was never verified as a deployed exploit. Its two true positives and two true negatives are reported separately from real-world known-bug coverage, which remains zero.
