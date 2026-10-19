# Next

## Deferred: deployed known-bug positives (the one gap to `field_accuracy_measurable`)

`corpus-benchmark` reports precision and recall over the five framework-agnostic
`scan` detectors, but `field_accuracy_measurable` stays false until at least five
deployed known-bug positives are scored. We have one (the historical GoonFi ELF).
Everything else in the corpus is either a source-built control pair or a deployed
clean control.

Two independent passes confirmed the quick path is a no-go: hand-built minimal
fixtures cannot produce a deployed positive. Real missing-signer, missing-owner,
type-cosplay and arbitrary-CPI bugs live in heavy DeFi and bridge programs. Anchor
auto-enforces owner and discriminator checks, so only native programs trip the
detectors, and a positive needs a baseline that runs the vulnerable instruction to
success, which requires heavy valid state (PDAs, pools, OpenBook markets, guardian
signatures). GoonFi only counts because its fixture was hydrated from a real
captured on-chain transaction, not synthesized.

The only real path is the GoonFi way, per named target:

1. Find an on-chain transaction that successfully ran the vulnerable instruction.
2. `capture` it, then `hydrate` the prior-slot account bytes from the archive RPC.
3. `reconstruct-slot` if earlier in-slot writers changed tracked accounts.
4. Confirm the baseline replays to success, then confirm `scan` flags the bug.

Each target is a bounded multi-step job that bills archive-RPC reads (roughly an
hour of expert work) with no guarantee the root cause maps to one of our five
detectors. Candidates, best first:

- **Raydium legacy AMM V3 LP-mint flaw** (June 2026, ~$1.34M). Clearest public
  root cause; preferred first target.
- **Aquifer** (Aug 2026).

Needs an explicit per-target go before spending archive-RPC effort. Do not launch a
new deployed-positive hunt without it.
