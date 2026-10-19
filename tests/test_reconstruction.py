import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from soldecomp import (CRATE_PATH, SYSCALL_HASHES, Instruction,
                       capture_cpi_instruction_data, detect_framework,
                       fingerprint_binary, ELF, murmur3_32,
                       prior_dependency_closure, resolve_sbf_input_account,
                       sbpf_version, scan_program, trace_memory_provenance)

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "replay/target/debug/soldecomp-replay"


class ReconstructionTests(unittest.TestCase):
    def test_transitive_writer_is_selected_before_direct_writer(self):
        def row(signature, accounts, failed=False):
            return {"transaction": {"signatures": [signature],
                                    "accountKeys": [
                                        {"pubkey": key, "writable": writable}
                                        for key, writable in accounts]},
                    "meta": {"err": "failed" if failed else None,
                             "fee": 5000 if failed else 0}}

        block = [row("source", [("input", True), ("reader", False)]),
                 row("failed", [("input", True)], failed=True),
                 row("direct", [("target", True), ("input", False)]),
                 row("target-tx", [("target", False)])]
        closure = prior_dependency_closure(block, 3, {"target"})
        self.assertEqual([item["signature"] for item in closure["writers"]],
                         ["source", "failed", "direct"])
        self.assertEqual(closure["writers"][1]["kind"], "failed_fee")
        self.assertEqual(closure["writers"][1]["fee_lamports"], 5000)
        self.assertEqual(set(closure["dependency_accounts"]),
                         {"target", "input", "reader"})

    def test_historical_goonfi_load_maps_to_mutated_token_amount(self):
        path = Path(__file__).resolve().parents[1] / "benchmarks/fixtures/goonfi-full-route.json"
        fixture = json.loads(path.read_text())
        mapping = resolve_sbf_input_account(fixture, 0x40000AB70, 8)
        self.assertEqual(mapping["account"],
                         "FKKpxrDezYSw5JoP2k5xaABPk2De3xvsU7gXkfsdJw3f")
        self.assertEqual(mapping["account_data_offset"], 64)

    def test_store_and_reload_keep_one_root_load(self):
        code = {0: Instruction(0, 0x79, 2, 1, 0, 0),
                8: Instruction(8, 0x7B, 10, 2, -8, 0),
                16: Instruction(16, 0x79, 3, 10, -8, 0),
                24: Instruction(24, 0x95, 0, 0, 0, 0)}

        def row(pc, amount=0, reload=0):
            regs = [0] * 12
            regs[1], regs[2], regs[3], regs[10], regs[11] = (
                0x100, amount, reload, 0x200, pc)
            return tuple(regs)

        before = [row(0), row(1, 7), row(2, 7), row(3, 7, 7)]
        after = [row(0), row(1, 9), row(2, 9), row(3, 9, 9)]
        result = trace_memory_provenance(before, after, code, {}, 0, 7, 9)
        self.assertEqual(len(result["root_loads"]), 1)
        self.assertEqual([event["kind"] for event in result["events"]],
                         ["source_load", "memory_store", "memory_reload"])

    def test_arithmetic_lineage_reaches_a_changed_store(self):
        code = {0: Instruction(0, 0x79, 2, 1, 0, 0),
                8: Instruction(8, 0x07, 2, 0, 0, 5),
                16: Instruction(16, 0x7B, 10, 2, -8, 0),
                24: Instruction(24, 0x95, 0, 0, 0, 0)}

        def row(pc, amount=0):
            regs = [0] * 12
            regs[1], regs[2], regs[10], regs[11] = 0x100, amount, 0x200, pc
            return tuple(regs)

        before = [row(0), row(1, 7), row(2, 12), row(3, 12)]
        after = [row(0), row(1, 9), row(2, 14), row(3, 14)]
        result = trace_memory_provenance(before, after, code, {}, 0, 7, 9)
        events = result["events"]
        self.assertEqual([event["kind"] for event in events],
                         ["source_load", "arithmetic", "memory_store"])
        self.assertEqual(events[1]["parents"], [events[0]["id"]])
        self.assertEqual(events[1]["baseline_output"], 12)
        self.assertEqual(events[1]["mutated_output"], 14)
        self.assertEqual(events[2]["parents"], [events[1]["id"]])

    def test_cpi_data_follows_memory_copy_syscall(self):
        code = {0: Instruction(0, 0x7B, 10, 2, 24, 0),
                8: Instruction(8, 0x7B, 10, 3, 32, 0),
                16: Instruction(16, 0x7B, 4, 5, 0, 0),
                24: Instruction(24, 0x72, 4, 0, 8, 0),
                32: Instruction(32, 0x85, 0, 0, 0, 0),
                40: Instruction(40, 0x85, 0, 0, 0, 0)}

        def row(pc):
            regs = [0] * 12
            regs[10] = 0x2000
            regs[2], regs[3], regs[4] = 0x4000, 9, 0x3000
            regs[5] = int.from_bytes(bytes([3]) + (42).to_bytes(7, "little"), "little")
            if pc == 4:
                regs[1], regs[2], regs[3] = 0x4000, 0x3000, 9
            else:
                regs[1] = 0x2000
            regs[11] = pc
            return tuple(regs)

        calls = capture_cpi_instruction_data(
            [row(pc) for pc in range(6)], code,
            {32: "sol_memcpy_", 40: "sol_invoke_signed_c"}, 0)
        self.assertEqual(calls[0]["spl_token_transfer_amount"], 42)

    def test_cpi_transfer_amount_requires_reconstructed_instruction_bytes(self):
        code = {0: Instruction(0, 0x7B, 10, 2, 24, 0),
                8: Instruction(8, 0x7B, 10, 3, 32, 0),
                16: Instruction(16, 0x7B, 4, 5, 0, 0),
                24: Instruction(24, 0x72, 4, 0, 8, 0),
                32: Instruction(32, 0x85, 0, 0, 0, 0)}

        def row(pc):
            regs = [0] * 12
            regs[1] = regs[10] = 0x2000
            regs[2], regs[3], regs[4] = 0x3000, 9, 0x3000
            regs[5] = int.from_bytes(bytes([3]) + (42).to_bytes(7, "little"), "little")
            regs[11] = pc
            return tuple(regs)

        calls = capture_cpi_instruction_data(
            [row(pc) for pc in range(5)], code, {32: "sol_invoke_signed_c"}, 0)
        self.assertEqual(calls[0]["spl_token_transfer_amount"], 42)
        self.assertEqual(calls[0]["data_hex"], "032a00000000000000")


class GeneralizationTests(unittest.TestCase):
    def test_murmur3_matches_solana_syscall_hash(self):
        # The sBPF loader uses this exact constant for the entrypoint symbol.
        self.assertEqual(murmur3_32(b"entrypoint"), 0x71E3CF81)
        self.assertEqual(SYSCALL_HASHES[0x71E3CF81], "entrypoint")
        self.assertIn(murmur3_32(b"sol_invoke_signed_c"), SYSCALL_HASHES)

    def test_sbpf_version_flags_modeling_gap(self):
        self.assertEqual(sbpf_version(0),
                         {"e_flags": 0, "version": "v0_or_v1_preversioning",
                          "fully_modeled": True})
        self.assertEqual(sbpf_version(2)["version"], "v2")
        self.assertFalse(sbpf_version(2)["fully_modeled"])
        self.assertEqual(sbpf_version(0x99)["version"], "unknown")

    def test_crate_path_parses_registry_versions(self):
        text = ("registry/src/index.crates.io-1949cf8c6b5b557f/anchor-lang-0.32.1/src/x.rs "
                "registry/src/index.crates.io-1949cf8c6b5b557f/solana-program-entrypoint-2.3.0/src/lib.rs")
        found = dict(CRATE_PATH.findall(text))
        self.assertEqual(found["anchor-lang"], "0.32.1")
        self.assertEqual(found["solana-program-entrypoint"], "2.3.0")

    def test_anchor_discriminator_known_answer(self):
        self.assertEqual(
            hashlib.sha256(b"global:initialize").digest()[:8].hex(),
            "afaf6d1f0d989bed")

    def test_detect_framework_identifies_anchor_and_crates(self):
        result = detect_framework(ROOT / "benchmarks/programs/security-examples.so", None)
        self.assertEqual(result["framework"], "anchor")
        self.assertEqual(result["fingerprint"]["anchor_version"], "0.32.1")
        self.assertTrue(result["sbpf"]["fully_modeled"])

    def test_fingerprint_reports_pinocchio_token_build(self):
        elf = ELF((ROOT / "benchmarks/programs/spl-token.so").read_bytes())
        self.assertTrue(fingerprint_binary(elf)["has_pinocchio"])

    @unittest.skipUnless(RUNNER.exists(), "replay runner not built")
    def test_scan_separates_owner_check_variants(self):
        with tempfile.TemporaryDirectory() as work:
            insecure = scan_program(ROOT / "benchmarks/fixtures/owner-insecure.json",
                                    Path(work) / "insecure", RUNNER, 8)
            secure = scan_program(ROOT / "benchmarks/fixtures/owner-secure.json",
                                  Path(work) / "secure", RUNNER, 8)
        self.assertIn("missing_owner", insecure["findings"])
        self.assertNotIn("missing_owner", secure["findings"])

    @unittest.skipUnless(RUNNER.exists(), "replay runner not built")
    def test_scan_detects_type_tag_substitution(self):
        with tempfile.TemporaryDirectory() as work:
            insecure = scan_program(ROOT / "benchmarks/fixtures/tag-insecure.json",
                                    Path(work) / "insecure", RUNNER, 8)
            secure = scan_program(ROOT / "benchmarks/fixtures/tag-secure.json",
                                  Path(work) / "secure", RUNNER, 8)
        self.assertIn("account_substitution", insecure["findings"])
        self.assertNotIn("account_substitution", secure["findings"])

    @unittest.skipUnless(RUNNER.exists(), "replay runner not built")
    def test_scan_detects_arbitrary_cpi(self):
        with tempfile.TemporaryDirectory() as work:
            insecure = scan_program(ROOT / "benchmarks/fixtures/cpi-insecure.json",
                                    Path(work) / "insecure", RUNNER, 8)
            secure = scan_program(ROOT / "benchmarks/fixtures/cpi-secure.json",
                                  Path(work) / "secure", RUNNER, 8)
        self.assertIn("arbitrary_cpi", insecure["findings"])
        self.assertNotIn("arbitrary_cpi", secure["findings"])


if __name__ == "__main__":
    unittest.main()
