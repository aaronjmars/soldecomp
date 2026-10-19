# soldecomp

Reverse-engineer, replay, and probe already-deployed Solana programs on your own machine, from bytecode, with no live-chain writes.

A local workbench for reconstructing Solana sBPF programs. It fetches a deployed ELF, exports a register-level lift, Ghidra C-like pseudocode, and call and data-flow evidence per detected function, builds candidate Rust with a pinned Solana toolchain, compares binaries, gates score regressions and suspicious source patterns, and replays pinned instructions or full transactions with controlled account changes. The Python CLI uses only the standard library; `decompile` needs Ghidra, `build` needs Solana platform tools, and `replay` needs the separate LiteSVM runner.

This is **not** automatic Rust source recovery. Ghidra output needs human review, function boundaries can be missed, and the scorer is a heuristic rather than OtterSec's unpublished implementation. Byte-identical compilation is the only conclusive build match.

> **Status: released as-is and no longer maintained.** This is a research
> workbench for defensive reverse engineering of already-deployed, publicly
> visible Solana program bytecode. It reconstructs and replays on-chain
> behavior to study it; it is not an exploit kit and every detector output is a
> hypothesis to verify by hand, not a proof of a reachable or profitable bug.

## What it does

- **Fetch and analyze** any deployed Solana program ELF: register-level lift, call graph, strings, sBPF ISA version, and resolved syscalls, no RPC beyond the fetch.
- **Decompile** to Ghidra C-like pseudocode with Solana syscall signatures and input-account field labels.
- **Trace** account values through arithmetic, branches, and CPIs as inspectable evidence, not a proof.
- **Detect framework** (Anchor, Pinocchio, or native), crate versions, toolchain, and instruction interface without running the program.
- **Replay** a pinned instruction or a full historical transaction in a patched LiteSVM, hydrating prior-slot account bytes and sysvars from an archive RPC, then mutate one input at a time and compare compute units, logs, and account effects.
- **Scan** for five common bug classes (missing signer, missing owner, account substitution, arbitrary CPI, balance sensitivity) against a labeled benchmark corpus that reports real precision and recall.
- **Build and compare** candidate Rust against the target with a pinned Solana toolchain, gated on a byte and score diff.

## Setup from a clone

Python 3.12 and Rust 1.99.1 are enough for the offline analyzer, pinned benchmark, and replay runner. The Python commands have no package dependencies. The LiteSVM patch and its lockfile are included in this repository.

```sh
git clone https://github.com/aaronjmars/decomp.git
cd decomp
cargo build --locked --manifest-path replay/Cargo.toml
python3 soldecomp.py benchmark benchmarks/manifest.json --out out/benchmark
```

The repository is currently private. Headless Ghidra is optional for `decompile` and the `benchmark --ghidra` extension. Building candidate Solana Rust programs requires Solana platform tools in addition to host Rust. Historical account capture requires an archive-capable RPC; do not put its key in a fixture or commit it. The offline benchmark needs no RPC.

## Try it

```sh
python3 soldecomp.py fetch PROGRAM_ID --out samples/program.so
python3 soldecomp.py analyze samples/program.so --out out/program
python3 soldecomp.py decompile samples/program.so --out out/program-decompiled
python3 soldecomp.py trace out/program-decompiled/flow.json --callee sol_invoke_signed_c
```

`fetch` accepts both legacy BPF Loader programs and upgradeable programs. It writes the ELF and a JSON file with the program ID, ProgramData account when present, observed slot, and SHA-256 hash. The default RPC is `https://api.mainnet-beta.solana.com`; use `--rpc URL` for another cluster or provider. The snapshot is the program version at the time of the RPC call. The current GoonFi deployment differs from the historical binary in the article.

Native built-in programs and non-ELF accounts are outside this tool's input format.

`analyze` writes:

- `analysis.json`: metadata, function boundaries, call graph, printable strings, direct string references, and an approximate leaf-first work order.
- `functions/<address>.txt`: one register-level lift per function.

The output uses virtual addresses from the ELF. A function named `sub_<address>` was inferred, not identified. The work order is only a starting order: cycles and inlining still need manual review. Strings can expose build paths and other embedded data from the program.

The analyzer now resolves named SBF call relocations from the ELF itself. Imported calls appear by name in the register lift and are not mistaken for local function starts. The count of inferred regions can therefore be lower than in older reports. Indirect calls can still hide function starts.

`analysis.json` also reports the sBPF ISA version from the ELF `e_flags` under `sbpf`. A value of `0` is the original pre-versioning format that this lifter fully models; a non-zero value selects a newer versioned ISA where a few ALU and call opcodes decode differently, and the analyzer adds a warning rather than silently lifting those as the classic set. In a static-syscall build (no call relocations), a `call` carries the murmur3-32 hash of the syscall name instead of a relocation symbol; the analyzer resolves those against a table of public Solana syscalls and lists them under `syscall_imports`, so they are named rather than counted as stray branch targets.

`decompile` runs Ghidra headless and writes `functions/<address>.c`, `functions/index.tsv`, `flow.json`, `ghidra.log`, and `decompile.json`. For `EM_SBF` (263), it copies the ELF and relabels the machine field to `EM_BPF` (247) so Ghidra selects its eBPF loader. The fetched original stays intact. This helps with familiar eBPF instructions but does not implement Solana-specific sBPF semantics; check suspicious output against the register lift. Use `--function 0x1234` to export one detected function. The tool does not handle native built-in programs or non-ELF accounts.

`flow.json` records Ghidra high P-code calls, loads, stores, arithmetic, branches, and returns for program code. Relocated syscall stubs are excluded because their synthetic self-calls duplicate actual callsites. Each input has a bounded backward expression that can identify a parameter, constant, load, or call result. Recognized public program IDs receive a symbol label. Direct pointers into the [standard aligned Solana input buffer](https://solana.com/docs/core/accounts/account-runtime) receive fixed field labels such as `account_count` and `account_0.data_len_if_unique`, including when the input pointer is forwarded through a direct call. The file includes the original ELF SHA-256 to tie the evidence to a program version. `trace` filters this evidence and, for a selected function, shows the callsites and argument sources that supply it:

```sh
python3 soldecomp.py trace out/program-decompiled/flow.json --function 0x1234 --kind call
python3 soldecomp.py trace out/program-decompiled/flow.json --function 0x1234 --parameter 1
python3 soldecomp.py trace out/program-decompiled/flow.json --callee sol_memcmp_
python3 soldecomp.py trace out/program-decompiled/flow.json --function 0x1234 --event 0x1250
python3 soldecomp.py trace out/program-decompiled/flow.json --function 0x1234 --op INT_SUB --no-callers
python3 soldecomp.py trace out/program-decompiled/flow.json --function 0x1234 --event 0x1250 \
  --via 0x5678 --via 0x9abc
```

With one selected event, `trace` also replaces its function parameters with each caller's argument sources in `event_inputs_at_caller`. Use `--caller 0x5678` to focus on one caller, or repeat `--via` to follow a chosen chain of callers from the selected function outward. Addresses refer to the ELF, so the same commands work with another Solana ELF. The expressions are evidence to inspect, not a proof that an account is trusted or a bug is exploitable. They stop after eight defining operations and leave unknown values explicit. Fixed input labels cover only the first account's header if that account is unique; later account offsets depend on data lengths and duplicate markers. Ghidra can infer overlapping functions, so one instruction may appear in more than one function record. Confirm any suspicious path against the register lift and a transaction test on the same deployed program version.

## Detect framework, version, and interface

`detect-framework` classifies a program without running it and recovers the shape later steps need to assign by hand:

```sh
python3 soldecomp.py detect-framework samples/program.so
python3 soldecomp.py detect-framework samples/program.so --idl program-idl.json --out out/framework.json
```

It reports the detected framework (`anchor`, `pinocchio`, `native`, or `unknown`) with the signals behind the call, the sBPF version, and a build fingerprint: crate names and versions, the Solana platform-tools toolchain marker, and a rustc commit when the panic paths expose one. On a security-examples build it recovers `anchor-lang 0.32.1`, `borsh 0.10.4`, and the `solana-*` crates from embedded registry paths; on the current SPL token build it reports the pinocchio rewrite. Instruction names logged by an Anchor `#[program]` as `Instruction: <Name>` are recovered with a guessed 8-byte discriminator. With `--idl`, an Anchor IDL (old or new format) supplies instruction names, per-account `writable` and `signer` flags, and discriminators directly, which is the general replacement for assigning account roles by hand. A fully stripped release can hide the crate and framework markers, the discriminator guess assumes the log name maps to a snake_case method, and an IDL passed here is trusted as given rather than verified against the deployed program.

## Scan for common bug classes

`scan` runs framework-agnostic detectors derived from the fixture's own account list, with no per-program spec:

```sh
python3 soldecomp.py scan out/replay-goonfi/fixture-pre-slot.json --out out/goonfi-scan
```

For each instruction signer it removes the signature and checks whether the call still succeeds (missing signer). For each read-only account it changes the owner to an unrelated program and checks whether the call still succeeds (missing owner check); read-only accounts are used so the result is not confounded by the runtime's own write-ownership guard, and signer accounts are skipped because a signer's authority is its signature rather than its owner. For each program-owned account it flips the leading 8 bytes, the Anchor discriminator or an equivalent type tag, and checks whether the call still succeeds (account substitution); this models the dominant real-world Solana bug class, a program that uses an account without validating its type. For each account the instruction carries as a program (a known program id or an executable snapshot), it replaces that program id with an unrelated one and checks whether the call still succeeds (arbitrary CPI); an isolated instruction only, since it rewrites the instruction. For each writable SPL token vault it runs the valid-transfer balance probe (balance sensitivity). Each finding is a hypothesis, not proof that an attacker can reach the state or profit, and the absence of a finding is not a safety proof: these detectors do not cover value, arithmetic, or PDA bug classes, and a program that intentionally uses no type tag is a benign account-substitution positive. The same mutations are declarable one at a time through `bug-checks`; `scan` only enumerates them automatically.

## Investigate a bug

1. Pin the deployed ELF and its hash for the transaction slot under review. Obtain the instruction's account list and any IDL or documentation, then assign account roles. `inspect` can suggest token-account and vault roles from ownership, but does not prove a semantic role such as `bid_vault`.
2. Use `trace` to follow an interesting account value into comparisons, arithmetic, branches, and syscalls. For the historical GoonFi binary, `--function 0x1e6c0 --event 0x1e970 --op INT_SUB --no-callers` exposes a subtraction between a value loaded through a caller-supplied pointer and a value loaded from another parameter at offset `0x688`. That is a candidate pricing calculation, not a validated bug.
3. Reproduce the hypothesis against that exact program version with realistic accounts, then change one input at a time and compare errors, logs, compute units, and account changes. `capture`, `hydrate`, `audit-slot`, `mutate`, `replay`, and `reconcile` provide that loop. An archive can supply account bytes as of the prior slot; `audit-slot` checks whether another transaction wrote a tracked account before the target within its slot. A byte-identical Rust rebuild is useful for complete source recovery but is not required to test a concrete behavior hypothesis.

Before export, `BindSolanaImports.java` reads named call relocations from the input ELF and applies public Solana syscall signatures to Ghidra's mistaken local call stubs. The signatures for supported calls follow the locally installed Pinocchio 0.9.2 syscall declarations; unknown calls stay untouched. `ApplySolanaContext.java` labels referenced System, Token, and Token 2022 program IDs and checks whether callers read `r0` after a function call. With the built-in eBPF processor, functions where Ghidra independently infers arguments but incorrectly shows `void` get those arguments committed and a tentative 64-bit return. The import and return fixes are disabled for the optional SolEmu processor, whose calling convention handles these hints differently. The context and evidence are in `solana-context.json` and `solana-imports.tsv`; `decompile.json` reports how many signatures were applied. A 64-bit return does not establish the Rust type.

An optional Solana-aware Ghidra processor is installed. Run it as a second view:

```sh
python3 soldecomp.py decompile samples/program.so \
  --ghidra .toolchains/ghidra/ghidra_12.1.4_SOLANA \
  --processor eBPFSol:LE:64:default --out out/program-solana
```

This is a locally patched build of [SolEmu-Ghidra](https://github.com/samsheff/SolEmu-Ghidra) in `vendor/sol-emu-ghidra`, adapted for Ghidra 12's removed relocation constants and manifest format. Its slow security analyzer is disabled by default. The extension lives in a separate Ghidra copy because its relocation handler otherwise changes results from the built-in processor. On the historical GoonFi ELF, the built-in processor exported 213 detected functions, while the Solana processor exported 191 code functions and reported 10 failures for external syscall stubs. Both exported all 64 project functions identified from the unstripped published build. The built-in processor remains the default. The extension can identify some Solana syscalls; neither processor covers every sBPF version or reconstructs Rust source.

## Replay a pinned instruction or transaction

The `replay/` Rust runner uses a small local patch of [LiteSVM](https://github.com/LiteSVM/litesvm) in `replay/vendor/litesvm-0.12.0`. The patch lets an isolated CPI receive transaction route data through its instructions sysvar. It loads the ELF only after checking its SHA-256, restores account bytes and lamports, runs the chosen instruction, then repeats from the same initial state for each mutation. The report records errors, logs, compute use, and account effects. SPL Token account amounts are decoded from bytes 64-71. The `changed_outcome` list compares effects, so adding tokens to a vault does not count as a changed swap merely because the vault started with more tokens.

Build the runner once. This Mac's self-contained Rust install uses the following environment; a normal Rust installation only needs `cargo build --locked --manifest-path replay/Cargo.toml`:

```sh
PATH="$PWD/.toolchains/rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH" \
  CARGO_HOME="$PWD/.toolchains/cargo" RUSTUP_HOME="$PWD/.toolchains/rustup" \
  DYLD_LIBRARY_PATH="$PWD/.toolchains/rustup/toolchains/stable-aarch64-apple-darwin/lib" \
  cargo build --locked --manifest-path replay/Cargo.toml
```

For a real transaction, select an outer instruction with `--instruction-index`. For a CPI made by another program, add `--inner-index`; CPI signer flags are not in the RPC instruction record, so a signer established from other evidence can be supplied with `--override-signer`. This example captures a GoonFi CPI and tests a change to a candidate vault balance:

```sh
python3 soldecomp.py capture 3pdBmRFjDMKPgpu7SDcnYi8DZPHfhxZisjqgAjwSXULuenuvApQtn6fHEzaQM7GnASvhCdWGxyX7Z6dDq8hixwRT \
  --elf samples/goonfi-current.so --instruction-index 2 --inner-index 4 \
  --override-signer 3LoAYHuSd7Gh8d7RTFnhvYtiTiefdZ5ByamU42vkzd76 \
  --out out/replay-goonfi-current/fixture.json
python3 soldecomp.py inspect out/replay-goonfi-current/fixture.json \
  --out out/replay-goonfi-current/roles.json
python3 soldecomp.py mutate out/replay-goonfi-current/fixture.json \
  --out out/replay-goonfi-current/fixture-mutated.json --name bid-vault-plus-10m \
  --account FKKpxrDezYSw5JoP2k5xaABPk2De3xvsU7gXkfsdJw3f \
  --token-amount-delta 10000000
python3 soldecomp.py replay out/replay-goonfi-current/fixture-mutated.json \
  --out out/replay-goonfi-current/report.json
```

`inspect` labels token accounts, their mint and authority, program-owned state, and likely vaults. For an inner CPI it also flags a token authority that may need a signer override; these are layout and ownership hints, not validated names. `mutate` also accepts `--bytes-hex` with `--offset`, `--lamports`, or `--instruction-hex`. Repeat it against the same fixture to add independent scenarios. Review `origin.program_version_verified`, `origin.state_exact`, and `limitations` before interpreting a result. `capture` checks the live ProgramData version, but [getMultipleAccounts](https://solana.com/docs/rpc/http/getmultipleaccounts) returns account bytes at its observation slot. `hydrate` checks the archived version, replaces account bytes with prior-slot data, and records Clock, Rent, EpochSchedule, LastRestartSlot, EpochRewards, and StakeHistory when available at the transaction slot. Add `--features` to read current feature-account activation slots and filter them by the transaction slot. This feature view can miss accounts that were removed later. For a CPI, the selected parent instruction is moved to index zero in a copy of the original instructions sysvar because the isolated run executes one top-level instruction. This keeps the route's program ID, accounts, and data, but does not reconstruct the exact instruction position or parent execution. Full transaction replay uses the runtime's original instructions sysvar instead. A fixture may set `origin.execution_slot` to choose a clock slot separate from its transaction slot. Such a clock override is a counterfactual unless backed by historical state.

### Archived transaction workflow

Set `SOLDECOMP_ARCHIVE_RPC` to an archive-capable Solana RPC URL. This workspace uses Alchemy's paid [Account Archive](https://www.alchemy.com/docs/solana/account-archive); its `getAccountInfo` accepts a historical `slot`. The local key is read inline from `pass` and is never written to a fixture:

```sh
export SOLDECOMP_ARCHIVE_RPC="https://solana-mainnet.g.alchemy.com/v2/$(pass show f0und/alchemy | head -n 1)"
python3 soldecomp.py hydrate out/demo/fixture-live.json --out out/demo/fixture-pre-slot.json
python3 soldecomp.py audit-slot out/demo/fixture-pre-slot.json --out out/demo/block-order.json
python3 soldecomp.py replay out/demo/fixture-pre-slot.json --out out/demo/local-replay.json
python3 soldecomp.py reconcile out/demo/fixture-pre-slot.json out/demo/local-replay.json \
  --out out/demo/reconciliation.json
```

`hydrate` verifies the archived executable against the pinned ELF, including ProgramData with only zero-filled extra space, and compares available lamport and token balances with the transaction's recorded pre-balances. The fixture still says `state_exact: false` because earlier transactions in the same slot or earlier instructions in the same transaction may have changed account data. `audit-slot` lists earlier successful transactions where a tracked account was writable. `reconcile` compares the isolated run both with full-transaction token deltas and with SPL Token transfers recorded under the selected CPI. The CPI comparison avoids attributing later swap legs to GoonFi. It recognizes `Transfer` and `TransferChecked`; fee, mint, burn, and other token operations need separate review.

If `audit-slot` finds an earlier writer, pin that writer's historical ELF, capture its instruction, hydrate its fixture from the prior slot, and replay it with full account bytes. Carry a changed account into the target fixture with `apply-state`:

```sh
python3 soldecomp.py replay out/demo/writer-pre-slot.json \
  --include-account-data --out out/demo/writer-report.json
python3 soldecomp.py apply-state out/demo/target-pre-slot.json out/demo/writer-report.json \
  --account ACCOUNT_ID --out out/demo/target-after-writer.json
python3 soldecomp.py replay out/demo/target-after-writer.json \
  --out out/demo/target-replay.json
```

`apply-state` checks that the target account matches the writer replay's initial hash and metadata, checks the resulting data hash, verifies the writer's program version, and records provenance. Replay earlier writers in transaction order. A matching local writer result is still a reconstruction: inspect its instruction, logs, compute use, and later writes before treating the carried state as the historical CPI input. Full account bytes appear only when `--include-account-data` is requested.

`reconstruct-slot` walks backwards from tracked target accounts through every earlier successful writer and every account that writer read. It also follows failed transactions when their fees reduced a needed payer balance. It captures each selected successful transaction, fetches its program version and prior-slot accounts, replays the complete transactions in block order, and carries intermediate account state into later writers. It checks account hashes before carrying the final state into the target fixture. A fixture that already contains earlier writer updates is rehydrated first. It also restores the parent route context for an isolated CPI. An archive RPC with historical account reads is required:

```sh
python3 soldecomp.py reconstruct-slot out/demo/fixture-pre-slot.json \
  --out out/demo/fixture-reconstructed.json
python3 soldecomp.py replay out/demo/fixture-reconstructed.json \
  --out out/demo/reconstructed-replay.json
```

To run a complete parent transaction locally, capture an outer instruction with `--full-transaction`, hydrate all accounts and executable versions, then replay. The runner deserializes and executes the original signed transaction bytes, including its address table lookups and all outer instructions. Signature and recent blockhash checks are disabled for historical replay; instruction bytes remain fixed. Account mutations still work.

```sh
python3 soldecomp.py capture SIGNATURE --elf samples/program.so \
  --instruction-index 0 --full-transaction --out out/demo/full-live.json
python3 soldecomp.py hydrate out/demo/full-live.json --out out/demo/full-pre-slot.json
python3 soldecomp.py replay out/demo/full-pre-slot.json --out out/demo/full-replay.json
```

Check full replay against the recorded transaction before using its mutation results. `reconcile` reports the first log and compute-budget difference for a full transaction. The historical oracle updater benchmark matches both success and 324 compute units. A newer Jupiter to ALPHA to GoonFi route completes locally after restoring the original instructions sysvar and historical Clock. Its local baseline and one vault mutation match the provider's archived simulation in logs, compute units, and observed token effects. Restoring five more sysvars and 222 active features leaves a 15 compute-unit difference from the recorded on-chain transaction. The first mismatch is a remaining-budget line at the first token CPI inside GoonFi; the token CPI and GoonFi report the same units consumed locally and on-chain. The exact earlier instruction that spent the extra 15 units is unresolved.

When the transaction falls within the provider's moving simulation window, run the original full transaction against archived state and one or more account changes:

```sh
python3 soldecomp.py archive-simulate out/demo/fixture-mutated.json \
  --name bid-vault-plus-10m --out out/demo/archive-compare.json
```

`archive-simulate` uses [Alchemy's simulateTransactionsAtSlot](https://www.alchemy.com/docs/chains/solana/solana-api-endpoints/simulate-transactions-at-slot), restores the previous slot, sets Clock to the transaction slot, and executes the original transaction including parent instructions. The baseline is always run. It allows up to four independent account mutations and does not alter chain state. The endpoint bills compute units and currently rejects old slots outside its moving window. Check the baseline token deltas against the recorded transaction before interpreting a mutation. Even matching token deltas do not prove identical logs or runtime behavior.

### Guided investigation and portable benchmark

`discover-fields` traces the pinned program and catalogs every directly observed account-data load with its account, offset, width, and role hints. Known SPL layouts supply a few field names; other fields remain unnamed. `probe` identifies writable SPL token accounts, prioritizes likely vaults, changes one token amount at a time, and reports payout or success changes as hypotheses. `probe-donation` instead runs an actual SPL Token transfer from a synthetic payer-controlled donor before the pinned instruction, with a matched no-transfer control. It reports the donor funding required and whether later token effects change. This tests a valid transfer path in LiteSVM, not whether the attacker can profit from it.

`trace-roles` replays a selected mutation twice, roots the changed value at a memory load, and follows register calculations, branches, exact virtual-address stores and reloads, and recognized memory-copy syscalls. It reconstructs C CPI instruction bytes from traced stores or copies and compares transfer amounts between runs. Pass a Ghidra `flow.json` to label operations and calls. Changed CPI bytes without a continuous source-to-sink lineage are listed as unproven. The GoonFi trace currently has such a gap: it records 156 arithmetic operations and 12 tainted branches, then loses lineage before the changed transfer. See `benchmarks/evidence/goonfi-arithmetic-gap.json`. Field discovery sees 84 fields in the original GoonFi replay and one in a small control (`benchmarks/evidence/field-discovery.json`). The independently built security-example ELF replays normally but currently fails when LiteSVM register tracing is enabled, so automatic field discovery is unavailable for that ELF. Program-specific field meanings and rules still need review.

```sh
python3 soldecomp.py discover-fields benchmarks/fixtures/goonfi-original.json \
  --out out/goonfi-fields.json
python3 soldecomp.py probe-donation benchmarks/fixtures/goonfi-original.json \
  --out out/goonfi-donation.json
python3 soldecomp.py probe out/demo/fixture-reconstructed.json \
  --out out/demo/probe.json
python3 soldecomp.py trace-roles out/demo/probe.probe-fixture.json \
  --name account-4-plus-100bp --flow out/demo/decompiled/flow.json \
  --out out/demo/role-trace.json
python3 soldecomp.py benchmark benchmarks/manifest.json --out out/benchmark
python3 soldecomp.py bug-checks benchmarks/bug-checks/guarded-insecure.json \
  --out out/guarded-security
```

The label-held-out benchmark keeps pinned case inputs in `benchmarks/blind/manifest.json` and expected labels in `benchmarks/blind/labels.json`. Detection does not read labels. Run it and score the predictions separately:

```sh
python3 soldecomp.py blind-benchmark benchmarks/blind/manifest.json --out out/blind-benchmark
python3 soldecomp.py score-blind out/blind-benchmark/predictions.json \
  benchmarks/blind/labels.json --out out/blind-benchmark/score.json
python3 soldecomp.py runtime-audit benchmarks/fixtures/goonfi-full-route.json \
  benchmarks/evidence/goonfi-full-runtime-diff.json --out out/goonfi-runtime-audit.json
```

`corpus-benchmark` scores the framework-agnostic `scan` detectors against a labeled corpus of pinned programs in `benchmarks/corpus/manifest.json`, so detector precision and recall are measured numbers rather than a single pair:

```sh
python3 soldecomp.py corpus-benchmark benchmarks/corpus/manifest.json --out out/corpus
```

Each case declares a true label per detector; a case may also declare an `expected_prediction` when a detector is known to disagree with that label. The confusion matrix always scores against the true label, while the pass gate scores against the expected prediction, so a documented limitation does not turn CI red. The seeded corpus holds the source-built missing-signer, missing-owner-check, type-discriminator and arbitrary-CPI pairs, the deployed GoonFi vulnerable and fixed versions, and valid transfers against the canonical deployed SPL Token and Token-2022 programs as deployed clean controls: thirteen scored verdicts across twelve cases, precision 0.83 and recall 1.0, the one false positive being the fixed GoonFi that stays balance sensitive. The balance detector recognizes only classic SPL Token vaults, so it is not scored on the Token-2022 case. `field_accuracy_measurable` stays false until at least five deployed known-bug positives are scored (recall across real programs needs deployed positives, not just any deployed case), and `detectors_without_corpus_case` names any detector with no label yet. The corpus is meant to grow with real deployed, labeled programs; the synthetic controls only verify detector wiring.

The original deployed GoonFi ELF is a published balance-trust bug positive. [OtterSec's reconstruction repo](https://github.com/renato-osec/goonfi-v2-decompiled#goonfi-v2) says the program was upgraded on October 6, 2026 to fix the reported bugs. Our later fixture pins an on-chain ELF deployed after that upgrade, making it a fixed-version control. The transfer probe flags both versions: one true positive and one false positive when treated as a bug detector. Ordinary balance sensitivity can remain after a fix. The oracle updater is an unrelated clean diagnostic and is excluded from specificity. This one vulnerable/fixed pair does not estimate field accuracy. See `benchmarks/evidence/deployed-blind-benchmark.json`. `runtime-audit` records pinned Clock, sysvars, feature activations and local crate versions, then attributes the 15-compute-unit discrepancy at log level. It shows equal GoonFi and Token CPI totals and a parent route total 15 units lower locally. The historical validator binary, removed feature accounts and cache state remain unknown, so the exact cause is unresolved. The input checklist follows the [Agave SVM specification](https://github.com/anza-xyz/agave/blob/master/svm/doc/spec.md); the [Solana syscall reference](https://solana.com/docs/core/programs/syscall-reference) identifies the CPI and memory operations traced here.

`bug-checks` reads program-specific account fields and limits from JSON. It runs authorization, replay protection, stale oracle, minimum output, and lending solvency checks. A check can run `prelude_instructions` as earlier transactions in the same LiteSVM instance. The runner reports each step separately and can assert exact account fields after the baseline and mutation. The benchmark includes two source-built insecure and fixed control pairs, a historical oracle-updater clean control, and two bug/fix pairs from an independently authored Solana example program. A third source-built pair, the missing owner check, is scored by `scan` and the corpus benchmark rather than by a declared bug-check kind. The independent cases remove an authority signature or reuse a prior instruction after a valid transaction. Both check the resulting vault balance; the replay pair also checks the nonce. Its current confusion matrix has six true positives, seven true negatives, no false positives, and no false negatives across these declared controls. The independent program is a teaching example, not a deployed exploit. That configured security-check benchmark has no verified deployed known-bug positive, so its 13/13 score does not estimate field accuracy. The separate label-held-out transfer benchmark below includes one published deployed GoonFi positive. The Memo, SPL Token, oracle updater, and GoonFi cases continue to check cross-program analysis and replay. Add `--ghidra PATH` to include headless Ghidra.

For a bounded dynamic trace, use a new trace directory and select ELF instruction addresses from `trace` or `analyze`:

```sh
python3 soldecomp.py replay out/replay-goonfi-historical/trace-donation-fixture.json \
  --out out/replay-goonfi-historical/trace-control-report.json \
  --trace-dir out/replay-goonfi-historical/traces-control
python3 soldecomp.py trace-exec out/reference/goonfi-original-onchain.so \
  out/replay-goonfi-historical/traces-control \
  --address 0x1e6c0 --address 0x1e970 --radius 1 \
  --fixture out/replay-goonfi-historical/trace-donation-fixture.json \
  --out out/replay-goonfi-historical/trace-control-evidence.json
```

`trace-exec` accepts only traces whose embedded executable hash matches the given ELF. It maps LiteSVM's instruction index to `.text` addresses and reports register values before each selected instruction, nearby instructions, and visit counts. With `--fixture`, it also labels registers equal to SPL token amounts in the baseline or a mutation. Equal numbers suggest an account to investigate; they do not prove data provenance. Identical scenario traces share one trace file. Relocated calls may have different instruction bytes from the file. Tracing incurs overhead, so omit `--trace-dir` for large mutation sweeps. A trace establishes execution and register values in the fixture, not historical chain state or the meaning of a memory pointer.

On the historical GoonFi ELF, a cross-version probe using a later account snapshot executes the swap path and visits `0x1e6c0` and `0x1e970` once each. At `0x1e970`, the instruction is `r4 = sub(r4, r1) as u64`. `r4` is 76,890,177 in the baseline, equal to the captured bid vault token amount, and rises to 100,076,890,177 when only that vault's amount rises by 100 billion. `r1` stays 150,000,000. Under a synthetic execution clock 12 slots after the account observation, the swap pays 50,017 bid units in the baseline and 52,856 after the bid vault change. Raising the other vault by 100 million leaves the payout at 50,017. The larger sweep in `out/replay-goonfi-historical/sweep-report.json` shows a dose response, followed by the program's price and inventory limits. This confirms balance-sensitive pricing in the original ELF under these test inputs. It does not reproduce the article's historical exploit: the instruction and accounts are from a later program version, and the clock and balance changes are synthetic.

## Build candidate Rust

```sh
python3 soldecomp.py build path/to/rust-project \
  --out out/candidate.so --target samples/program.so
```

The project must be a Cargo `cdylib` targeting `sbpf-solana-solana`. `build` invokes the Cargo and rustc bundled with Solana platform-tools v1.48, strips the result, and writes build and comparison reports beside the ELF. Use `--toolchain PATH` for a different platform-tools release when the target was built with it. Pin dependencies in `Cargo.lock` and use the original build settings. A host-specific build can differ even when the Rust source is right, so reproduce the original build host for final byte equality.

## Score and gate a candidate build

```sh
python3 soldecomp.py compare samples/program.so candidate.so --out out/compare.json
python3 soldecomp.py judge samples/program.so candidate.so \
  --baseline previous-candidate.so --source candidate-source \
  --out out/judge.json
```

`compare` checks whole-file SHA-256 equality and scores aligned function instructions. This implementation charges 100 for a missing or extra instruction, 60 for an opcode substitution, 5 for changed operands, plus the absolute memory-offset difference. The [OtterSec article](https://osec.io/blog/goonfi-decompilation/) instead specifies 60 for an instruction in the wrong order. Its exact alignment, function mapping, library exclusion, and compiler-pass cheat checks are not published or reproduced here. An `--out` file contains every function score. Treat scores as a debugging hint, not a claim of equivalent behavior or equivalent source.

Functions match by symbol name where possible. Stripped binaries with equal function counts fall back to their order in `.text`; this is provisional. For a changed stripped binary, the judge requires an explicit `--map` JSON object of target address to candidate address, for example `{"0x9b8": "0xa00"}`. Use `--baseline-map` too if the previous candidate used other function addresses. A judge pass requires an improved total score, no function regression, no unmapped function, and no flagged source pattern. An exact binary match passes without a baseline. The source scan is a basic text filter, not a Rust parser or an LLVM pass.

When an unstripped candidate ELF is available, `compare --symbols-from PATH --project-crate NAME` annotates matched functions using legacy Rust symbol prefixes. Repeat `--project-crate` for each local crate. Its project, library, and unknown subtotals help isolate source work, but they are not verified library matches. The `judge` command still uses its original total score and explicit mapping gate.

To reach the article's byte-identical Rust result for a new program, a worker still needs source and type recovery, dependency identification, correct compiler settings, repeated build and score passes, review of behavior, and a final whole-binary match. The [Patina research tools](https://github.com/renato-osec/patina-research) currently require Binary Ninja for their agents, and [bn-ebpf-solana](https://github.com/otter-sec/bn-ebpf-solana) is a Binary Ninja plugin. Binary Ninja Free has no plugin API; Personal has no headless API. The headless Patina pipeline needs a Commercial or Ultimate license. [decomp.me](https://github.com/decompme/decomp.me) is a collaborative compiler matching site, and [Solana Verifiable Build](https://github.com/otter-sec/solana-verifiable-build) verifies a completed source build against deployment.

## Agent-assisted function review

Use `--keep-project` to retain Ghidra's analyzed database after the Solana import and context scripts run. The default `decompile` still deletes its temporary project. Pick a fresh output directory for each retained project:

```sh
python3 soldecomp.py decompile samples/program.so --out out/program-agent --keep-project
python3 soldecomp.py packet out/program-agent/flow.json \
  --function 0x1234 --event 0x1250 --out out/program-agent/function-packet.json
```

`packet` saves the original ELF hash, C-like pseudocode, selected high P-code evidence, and caller argument sources in one JSON file. Without `--event`, it includes up to 80 operation records by default; use `--max-events` to change that bound. A full `decompile` export gives it caller evidence. `--function` makes a faster one-function export, so its packet has no caller records outside that function.

The workspace-only [ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc) install can open the retained project. It uses a persistent local Ghidra process, so annotations and types can be edited and queried without rerunning the exporter:

```sh
export GHIDRA_RPC_STATE_DIR="$PWD/.toolchains/ghidra-rpc-state"
export JAVA_TOOL_OPTIONS="-Duser.home=$PWD/.toolchains/ghidra-home"
export GHIDRA_RPC_PROJECT="$PWD/out/program-agent/project/soldecomp.gpr"
export GHIDRA_RPC_BINARY="$(basename "$(jq -r .project_binary out/program-agent/decompile.json)")"
.toolchains/ghidra-rpc/bin/ghidra-rpc start --project "$GHIDRA_RPC_PROJECT" \
  --headless --detach --ghidra-install-dir "$PWD/.toolchains/ghidra/ghidra_12.1.4_PUBLIC"
.toolchains/ghidra-rpc/bin/ghidra-rpc load \
  "$(jq -r .project_binary out/program-agent/decompile.json)"
.toolchains/ghidra-rpc/bin/ghidra-rpc decompile "$GHIDRA_RPC_BINARY" 0x1234
.toolchains/ghidra-rpc/bin/ghidra-rpc xrefs-to "$GHIDRA_RPC_BINARY" 0x1234
.toolchains/ghidra-rpc/bin/ghidra-rpc stop
```

On the historical GoonFi binary, a fresh ghidra-rpc import mislabeled a relocated Solana syscall as a local function. Opening the retained `soldecomp` project kept the `sol_get_last_restart_slot` relocation name. The pricing candidate at `0x1e6c0` has three callers, and the annotation `candidate_pricing_logic` persisted after a daemon restart. This tests interactive analysis; it does not validate the account roles or a bug.

For Rust reconstruction, use the bounded pattern from [upstream ReAgent](https://github.com/Dryxio/reagent): inspect one function packet, write one candidate, have an independent checker review it, compile with `build`, then run `judge` against the previous candidate. Keep each round's packet, code, build log, score and checker notes together. Stop repeated candidates without a score or behavior improvement. `build` and `judge` already provide the deterministic gates, while `packet` gives each round a stable evidence input. The autonomous Rust source generator and checker are not implemented here; ReAgent's own source overlay and parity engine target C/C++.

## Ethereum scope

A comparable Ethereum workflow needs a separate EVM bytecode frontend. The shared investigation method is to pin the deployed code and state, recover enough logic to form a hypothesis, and replay it on the same version. The chain-specific inputs and tools differ:

| Stage | Solana sBPF here | Ethereum EVM requirement |
| --- | --- | --- |
| Pin target | ELF, program ID and deployment slot | Runtime bytecode at address and block; resolve proxy implementation at that block and retain the proxy's storage context |
| Recover interface and state | Instruction data, account order, IDL and account bytes | ABI or four-byte selectors, calldata, storage layout, events, external calls and proxy slots |
| Decompile | Ghidra eBPF view plus Solana import/context fixes | EVM-aware disassembler/decompiler such as [Heimdall](https://github.com/Jon-Becker/heimdall-rs); Ghidra's eBPF processor is not applicable |
| Test a hypothesis | Matching Solana accounts and a transaction replay harness | [Foundry](https://www.getfoundry.sh/forge/index.html) tests or [Anvil](https://www.getfoundry.sh/anvil/index.html) fork at the relevant block, with traces and state assertions |
| Rebuild source | Rust, Solana platform-tools, crate versions and build host | Solidity/Vyper compiler version, optimizer, EVM version, libraries, immutables and metadata settings |

Check for verified source before reconstructing a closed-source contract. [Solidity metadata](https://docs.soliditylang.org/en/latest/metadata.html) can identify compiler settings and source hashes; [Sourcify](https://docs.sourcify.dev/docs/exact-match-vs-match/) distinguishes an exact match from a match that excludes the metadata hash. Even comments or source paths can change an exact-match Solidity binary because the compiler appends a metadata fingerprint. Proxy analysis must follow `delegatecall` to the implementation while preserving the proxy's storage, as described in [ERC-1967](https://eips.ethereum.org/EIPS/eip-1967). A byte-identical source build helps establish provenance but is not required to demonstrate a bug with a reproducible fork test.

Foundry `forge`, `cast`, and `anvil` 1.8.5 and `solc` 0.8.28 are already installed on this Mac. Heimdall and source-based [Slither](https://github.com/crytic/slither) are not installed. The Ethereum frontend and a chosen-contract benchmark have not yet been built.

## Installed here

- Rust 1.99.1: `.toolchains/cargo/bin/rustc` and `.toolchains/cargo/bin/cargo`. Set `RUSTUP_HOME=$PWD/.toolchains/rustup` and `CARGO_HOME=$PWD/.toolchains/cargo` when using them directly.
- Solana platform-tools v1.48 for macOS arm64: `.toolchains/platform-tools-v1.48`. Its bundled rustc is 1.84.1-dev; `build` uses its bundled Cargo too.
- LiteSVM 0.12.0 replay runner: `replay/`, pinned in `replay/Cargo.lock` and built with host Rust 1.99.1.
- Ghidra 12.1.4 with its macOS arm64 native decompiler built: `.toolchains/ghidra/ghidra_12.1.4_PUBLIC`.
- Optional Solana-aware Ghidra extension built and installed in the separate `.toolchains/ghidra/ghidra_12.1.4_SOLANA` copy. Its patched source is in `vendor/sol-emu-ghidra`.
- Local clones of Patina, bn-ebpf-solana, and the published GoonFi source in `vendor/`. Patina's `chela` extractor was built in `.toolchains/patina-chela`; on the stripped GoonFi ELF it returns no crate metadata.
- Binary Ninja is not installed because no license or licensed installer was available locally. Its Free edition cannot run the needed plugin or Patina agents.

## Local validation

The included `samples/memo.so` was fetched from mainnet program `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`: 74,800 bytes, 7,024 decoded instructions, 196 inferred function regions after import-call correction. `samples/goonfi-current.so` was fetched from `goonuddtQRrWqqn5nFyczVKaie28f3kDkHWkHtURSLE`: 292,384 bytes, 27,223 instructions, 194 inferred function regions. The current GoonFi binary is `EM_SBF` and was upgraded after the article's original snapshot. Built-in Ghidra exported 213 functions from this newer binary into `out/goonfi-current-decompiled/functions`.

On Memo, comparison to the same ELF returned a zero score and exact SHA-256 match. A one-register mutation returned score 5. The judge rejected it against the exact baseline and accepted the reverse improvement. Ghidra exported C-like pseudocode for 203 Memo functions.

The traced replay also works on the unrelated Memo ELF: `out/replay-memo/report-traced.json` contains two successful scenarios, and `out/replay-memo/trace-evidence.json` maps entry instruction `0x9b8` to one visit in each scenario. The separate SPL Token ELF exported 88 functions and 28,331 flow events with no failures in `out/spl-token-flow-full/decompile.json`. The flow export completed on both unrelated ELFs with no flow failures: 183 program functions and 8,949 operation records for the historical GoonFi binary in `out/goonfi-flow-full/flow.json`, and 202 program functions and 3,194 records for Memo in `out/memo-flow-full/flow.json`. For GoonFi, `trace --function 0x32fd8 --event 0x32ff0 --via 0x250f0 --via 0x3990 --via 0x16a38 --via 0x21fc8` follows a comparison through four call edges to the entrypoint. The pricing function at `0x1e6c0` exposes the candidate subtraction at `0x1e970`. The entrypoint reads the account count and first unique account's data length from the documented Solana input offsets. For Memo, `trace --callee sol_log_` finds six call records, and the input pointer passed into helper `0x1a00` is labeled at its account count and first account marker reads. These records are starting points for manual review, not independently verified account types or vulnerabilities.

The original GoonFi ELF was reconstructed from its deployment transactions at slot 448984043 in `out/reference/goonfi-original-onchain.so`. Its SHA-256 is `6a2a8670a56b25baac9f956c428358697b537fab7d0c3ebc13eeb880600f767d`, matching the published reference. Archived ProgramData at the historical slot contains those exact 243,080 ELF bytes followed by 9,304 zero bytes of allocated space. This ELF ran from deployment slot 448984043 until it was superseded at slot 451334772; hashing the full allocated account data gives a different hash, but the executable prefix matches. The register-level analyzer found 26,432 instructions in 192 inferred function regions in `out/goonfi-context-analysis`, including 33 named import callsites. The isolated built-in Ghidra installation exported 213 detected functions in `out/goonfi-import-bound/functions`. The published Rust compiles locally to a 243,080-byte candidate in `out/reference/goonfi-macos-build-via-cli.so`, but its SHA-256 is `00a9c878b5eadc8db25818ae1bd0fb9717740319a42a8ffa7220ede3d14c6c2a`, with 8,552 differing bytes. The publisher's exact build script uses **Linux x86_64** platform-tools. This Mac build does not establish or refute source equivalence.

For the local GoonFi comparison, run:

```sh
python3 soldecomp.py compare out/reference/goonfi-original-onchain.so \
  out/reference/goonfi-macos-build-via-cli.so \
  --symbols-from vendor/goonfi-v2-decompiled/target/sbpf-solana-solana/release/goonfi_v2.so \
  --project-crate goonfi_v2 --project-crate goonfi_common \
  --project-crate goonfi_account_validation --project-crate oracle_asm \
  --out out/reference/goonfi-annotated-compare.json
```

The unstripped Mac build identifies 64 project functions, all at the same addresses in the historical ELF. Ghidra exported pseudocode for all 64. With import callsites excluded from function boundaries, 37 match instruction-for-instruction; the other 27 have the same instruction count and opcode sequence, with 136 changed operands. The provisional project-only score is 680. This comparison uses the **published reconstructed Rust**, so it tests the build and matching tools, not independent Rust recovery from Ghidra output. In the improved Ghidra output at `out/goonfi-import-bound/functions`, function `0x120` returns a 64-bit maximum instead of showing `void`, `0x250f0` uses `SOLANA_SYSTEM_PROGRAM_ID`, and the `0x32fd8` comparison wrapper passes four arguments to `sol_memcmp_` and returns the comparison result instead of returning a constant zero. The swap function shows arguments to `sol_log_` and `sol_invoke_signed_c`. Thirty of 33 named import callsites received signatures; two `abort` calls and one `custom_panic` call were left untyped. These annotations use no published GoonFi source.

The LiteSVM smoke test loaded the historical GoonFi ELF by its published hash. Empty instruction data returned `InvalidInstructionData`; one byte with no accounts returned `NotEnoughAccountKeys`. Those failures show that the binary executes, not that the reported bug is reproduced.

The newer GoonFi ELF was replayed using a real 14-account CPI from transaction `3pdBmRFjDMKPgpu7SDcnYi8DZPHfhxZisjqgAjwSXULuenuvApQtn6fHEzaQM7GnASvhCdWGxyX7Z6dDq8hixwRT` at slot 458251039. The live ProgramData still matched SHA-256 `a24aa13a0a9a4d7d1c8752cc9d9a566a5fae3bc20ba0ca3ba11368abd613e43c`, deployed at slot 453915006. The account snapshot was observed at slot 458252203, so it is not the transaction's pre-state. `inspect` identified account indices 4 and 5 as vault candidates and flagged account 0 as a possible missing CPI signer before the override. That signer flag was inferred from the user token accounts and supplied manually. In this local run, the baseline transferred 50,912 raw bid units to the user. Adding 10,000,000 raw units to the candidate bid vault changed that to 50,913; adding 100,000,000 raw units to the other vault left it at 50,912. The report is `out/replay-goonfi-current/report.json`. This is a controlled observation on the newer program with later account state, not a reproduction of the article's historical exploit.

An archived real transaction at slot 450000000, `26atQZKgYQaBWmdvWmy3Y9NXaJvE4zE5QbM1Xs9ATwUTBXL8rFZKbuGCPvigguxQegRnCASBP9AixWR4hKtgD2Q2`, used the published ELF. `out/replay-goonfi-old-real/fixture-pre-slot.json` passed 10 lamport and four token pre-balance checks. The selected swap was transaction 884 of 1,721. The first isolated run paid 3,801,354 raw bid units, 389 fewer than the recorded 3,801,743, because its prior-slot oracle bytes were stale. `out/replay-goonfi-old-real/block-order.json` identified oracle-writable transactions at indices 133 and 492.

The verified 512-byte oracle updater ELF is in `out/reference/oracle-updater-onchain.so`. Replaying the first update from archived state wrote a new 32-byte oracle value and used 24 compute units, matching its on-chain compute use. The second update used the same input, made no oracle change, and used 4 compute units, also matching on-chain. `apply-state` carried the first result into `out/replay-goonfi-old-real/fixture-oracle-reconstructed.json`. The GoonFi replay then paid exactly 3,801,743 raw bid units, matched both recorded CPI token transfers and its price log, and used 39,388 local compute units versus 39,384 reported for the on-chain CPI. The local reconciliation in `out/replay-goonfi-old-real/reconciliation-oracle-reconstructed.json` has no target-transfer difference.

`reconstruct-slot` now follows the full dependency closure: 11 earlier successful transactions instead of two direct oracle writers. All 11 local compute totals match their recorded totals, and the final captured account bytes match the earlier pinned fixture. The original GoonFi replay still pays 3,801,743 raw bid units and uses 39,388 local CPI compute units. The offline benchmark passes 17 of 17 analysis and replay cases and 13 of 13 labeled security checks. Two positive checks come from an independently authored teaching program; none are verified real-world exploit detections. A separate `corpus-benchmark` scores the five framework-agnostic detectors over twelve labeled cases, four of them deployed programs.

The expanded Ghidra import table was checked on SPL Token. Its `sol_get_sysvar` call now shows four typed arguments in the exported C-like function at `0x169a8`; 16 of 17 named call stubs received signatures in that run. Memo's entrypoint also exported without a decompiler failure. Binary Ninja and Patina remain optional licensed integrations rather than part of this repository's default path.

The corrected-state donation sweep in `out/replay-goonfi-old-real/sweep-oracle-report.json` increased the output when only the bid vault balance increased, while changing the ask vault did not. `out/replay-goonfi-old-real/trace-evidence.json` shows the bid vault amount in register `r4` immediately before the subtraction at `0x1e970`. This supports the balance-sensitive pricing hypothesis in the exact historical ELF. It does not establish that a profitable attack was reachable or that every part of the transaction was reproduced. The provider's full-transaction simulator starts after this ELF was upgraded, so it cannot run this historical transaction.

A newer GoonFi transaction at slot 458251039 has no prior successful writes to tracked accounts in its block, recorded in `out/replay-goonfi-current/block-order.json`. With parent route context, the isolated CPI paid 50,951 raw bid units, exactly matching the recorded CPI transfers in `out/replay-goonfi-current/reconciliation-route-context.json`. Full archived transaction simulation matched all observed token-account deltas; adding 10,000,000 raw bid vault units changed the payout to 50,952 in `out/replay-goonfi-current/archive-compare.json`. The provider's simulation logs differed from the recorded transaction at a later token-program compute-budget line, so this is a token-effect match, not a byte-identical transaction execution.

The local full parent replay matches the provider's archived simulation for baseline and bid vault mutation: 117,562 and 117,557 compute units, identical logs, and bid vault changes of -50,951 and -50,952 raw units. The recorded on-chain baseline used 117,577 compute units. A structured runtime comparison finds the first 15-unit budget difference at log index 21, before the first token CPI finishes inside GoonFi. Restoring five further sysvars and the filtered feature set did not change the local total. The differential memory trace identifies one source load from the bid vault's SPL token amount at data offset 64, follows 10 stores and 10 reloads, and reconstructs two later token CPI transfer instructions from memory. The first transfer stays at 41,536,364 raw units; the second changes from 50,951 to 50,952. The trace does not yet prove every arithmetic dependency between that input load and the second transfer.

The earlier static comparison summary is in `out/reference/goonfi-benchmark.json`; archived replay evidence is in `out/replay-goonfi-old-real/` and `out/replay-goonfi-current/`.

## Sources

- [Breaking open a propAMM](https://osec.io/blog/goonfi-decompilation/): function scoring weights, gate, and cheat constraints.
- [GoonFi V2 reconstructed source](https://github.com/renato-osec/goonfi-v2-decompiled): example of a finished byte-identical reconstruction and its build script.
- [Patina research](https://github.com/renato-osec/patina-research) and [bn-ebpf-solana](https://github.com/otter-sec/bn-ebpf-solana): type and lifting machinery.
- [Solana sBPF VM](https://github.com/anza-xyz/sbpf): instruction set and version differences.
- [LiteSVM](https://github.com/LiteSVM/litesvm): local SVM execution and account restoration for replay.
- [LiteSVM sysvar API](https://solana.com/docs/tools/litesvm/api-reference/time-and-sysvars): restoring typed runtime sysvars.
- [Coral Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks): public missing-signer example that informed one synthetic benchmark pair.
- [Solana Security Examples](https://github.com/Aypp23/solana-security-examples/tree/e0870e93453100828140267d44252dbbe4c3f933): independently authored missing-signer and replay-protection bug/fix pairs compiled into the pinned SBF benchmark ELF.
- [Alchemy Account Archive](https://www.alchemy.com/docs/solana/account-archive) and [simulateTransactionsAtSlot](https://www.alchemy.com/docs/chains/solana/solana-api-endpoints/simulate-transactions-at-slot): historical account reads and full transaction simulation.
- [Solana getTransaction](https://solana.com/docs/rpc/http/gettransaction) and [getMultipleAccounts](https://solana.com/docs/rpc/http/getmultipleaccounts): transaction metadata and live account snapshots.
- [SPL Token Account layout](https://github.com/solana-program/token/blob/main/interface/src/state.rs): mint, authority, and amount offsets used by `inspect` and `replay`.
- [Solana syscall declarations](https://github.com/anza-xyz/solana-sdk/blob/master/define-syscall/src/definitions.rs): public argument and return types for import signatures.
- [Solana core programs](https://solana.com/docs/core/programs/builtin-programs) and [token program IDs](https://solana.com/docs/references/terminology): public constants recognized by the context pass.
- [Ghidra compiler specifications](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/doc/cspec.xml) and [parameter commit API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunctionDBUtil.html): calling conventions and preserving inferred arguments.

## License and third-party code

This project is released under the MIT License; see [LICENSE](LICENSE).

It vendors a modified copy of [LiteSVM](https://github.com/LiteSVM/litesvm)
0.12.0 under `replay/vendor/litesvm-0.12.0/`. LiteSVM is licensed under
Apache-2.0; that subdirectory keeps its own `LICENSE` and a `CHANGES.md`
describing the two methods added for isolated-CPI replay, and remains under
Apache-2.0 rather than this repository's MIT license. The optional
SolEmu-Ghidra processor is a separate Apache-2.0 project fetched at setup time
and is not included here. Benchmark `.so` files under `benchmarks/programs/`
are either compiled from the source controls in this repository or public,
already-deployed on-chain program bytecode.
