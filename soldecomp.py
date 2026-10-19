#!/usr/bin/env python3
"""Solana sBPF triage, C-like decompilation, and Rust build feedback.

The Python CLI uses the standard library. Ghidra and Solana platform tools are
required for decompilation and candidate builds. Rust source recovery is manual.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


EM_BPF = 247
EM_SBF = 263
ELF_HEADER = struct.Struct("<HHIQQQIHHHHHH")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
INSN = struct.Struct("<BBhi")
REL = struct.Struct("<QQ")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
KNOWN_PROGRAM_IDS = {
    "SOLANA_SYSTEM_PROGRAM_ID": "11111111111111111111111111111111",
    "SOLANA_TOKEN_PROGRAM_ID": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "SOLANA_TOKEN_2022_PROGRAM_ID": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
}
OPS = {
    0x00: "add", 0x10: "sub", 0x20: "mul", 0x30: "div",
    0x40: "or", 0x50: "and", 0x60: "lsh", 0x70: "rsh",
    0x80: "neg", 0x90: "mod", 0xA0: "xor", 0xB0: "mov",
    0xC0: "arsh", 0xD0: "end",
}
JMPS = {
    0x10: "==", 0x20: ">", 0x30: ">=", 0x40: "&",
    0x50: "!=", 0x60: "s>", 0x70: "s>=", 0xA0: "<",
    0xB0: "<=", 0xC0: "s<", 0xD0: "s<=",
}
SIZES = {0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}
# Solana sBPF records the ISA version in the ELF e_flags for versioned builds.
# 0 is the original pre-versioning format: the loader selects v0/v1 by runtime
# feature gate, and this lifter models that classic instruction set. Non-zero
# values select a specific versioned ISA at load time; the decode of a few ALU
# and call opcodes differs there, so those are reported but flagged as not fully
# modeled rather than silently lifted as the classic set.
SBPF_VERSIONS = {0: "v0_or_v1_preversioning", 1: "v1", 2: "v2", 3: "v3",
                 0x20: "v2_legacy_flag"}
FULLY_MODELED_SBPF = {0}
# Public Solana syscall names. In static-syscall builds (no call relocations)
# a `call imm` carries the murmur3-32 hash of the name instead of a relocation,
# so a name-to-hash table recovers the callee that older binaries exposed as a
# relocation symbol. Sourced from the Solana define-syscall declarations.
SYSCALL_NAMES = [
    "abort", "sol_panic_", "custom_panic", "sol_log_", "sol_log_64_",
    "sol_log_compute_units_", "sol_log_pubkey", "sol_log_data",
    "sol_create_program_address", "sol_try_find_program_address", "sol_sha256",
    "sol_keccak256", "sol_blake3", "sol_secp256k1_recover", "sol_poseidon",
    "sol_get_clock_sysvar", "sol_get_epoch_schedule_sysvar", "sol_get_fees_sysvar",
    "sol_get_rent_sysvar", "sol_get_last_restart_slot", "sol_get_epoch_rewards_sysvar",
    "sol_memcpy_", "sol_memmove_", "sol_memset_", "sol_memcmp_",
    "sol_invoke_signed_c", "sol_invoke_signed_rust", "sol_alloc_free_",
    "sol_set_return_data", "sol_get_return_data", "sol_get_stack_height",
    "sol_get_processed_sibling_instruction", "sol_curve_validate_point",
    "sol_curve_group_op", "sol_curve_multiscalar_mul", "sol_curve_pairing_map",
    "sol_big_mod_exp", "sol_remaining_compute_units", "sol_get_sysvar",
    "sol_get_epoch_stake", "sol_alt_bn128_group_op", "sol_alt_bn128_compression",
    "entrypoint",
]


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def elf_match_mode(expected: bytes, onchain: bytes) -> str | None:
    """Match an ELF to ProgramData that may reserve zero-filled extra space."""
    if onchain == expected:
        return "exact_bytes"
    if (len(onchain) > len(expected) and onchain.startswith(expected) and
            not any(onchain[len(expected):])):
        return "zero_padded_prefix"
    return None


def b58decode(value: str) -> bytes:
    need(bool(value) and all(char in B58 for char in value), "invalid base58 address")
    number = 0
    for char in value:
        number = number * 58 + B58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\0" * (len(value) - len(value.lstrip("1"))) + raw


def b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    result = ""
    while number:
        number, rem = divmod(number, 58)
        result = B58[rem] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def rpc(url: str, method: str, params: list) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(url, payload, {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    need("error" not in result, f"RPC {method}: {result.get('error')}")
    return result["result"]


def account(url: str, address: str) -> tuple[dict, int]:
    result = rpc(url, "getAccountInfo", [address, {"encoding": "base64"}])
    value = result["value"]
    need(value is not None, f"account {address} does not exist")
    need(value["data"][1] == "base64", "RPC did not return base64")
    return {**value, "raw": base64.b64decode(value["data"][0], validate=True)}, result["context"]["slot"]


def fetch(program_id: str, url: str, output: Path) -> dict:
    need(len(b58decode(program_id)) == 32, "program ID must decode to 32 bytes")
    info, slot = account(url, program_id)
    need(info["executable"], "account is not executable")
    owner = info["owner"]
    raw = info["raw"]
    programdata = None
    deployed_at_slot = None
    data_observed_slot = None
    if owner == "BPFLoaderUpgradeab1e11111111111111111111111":
        need(len(raw) >= 36 and struct.unpack_from("<I", raw)[0] == 2,
             "invalid upgradeable Program account")
        programdata = b58encode(raw[4:36])
        data, data_observed_slot = account(url, programdata)
        need(data["owner"] == owner, "ProgramData has unexpected owner")
        raw = data["raw"]
        need(len(raw) >= 45 and struct.unpack_from("<I", raw)[0] == 3,
             "invalid upgradeable ProgramData account")
        deployed_at_slot = struct.unpack_from("<Q", raw, 4)[0]
        # Solana reserves 45 bytes for ProgramData metadata, even with no authority.
        raw = raw[45:]
    else:
        need(owner in {"BPFLoader2111111111111111111111111111111111",
                       "BPFLoader1111111111111111111111111111111111"},
             f"unsupported executable owner: {owner}")
    need(raw.startswith(b"\x7fELF"), "program bytes do not start with ELF")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    meta = {"program_id": program_id, "owner": owner, "programdata": programdata,
            "observed_slot": slot, "programdata_observed_slot": data_observed_slot,
            "deployed_at_slot": deployed_at_slot,
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "rpc": url}
    output.with_suffix(output.suffix + ".json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


@dataclass
class Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    entsize: int


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    section: int
    kind: int


class ELF:
    def __init__(self, data: bytes):
        need(len(data) >= 64 and data[:4] == b"\x7fELF", "not an ELF")
        need(data[4:6] == b"\x02\x01", "only little-endian ELF64 is supported")
        header = ELF_HEADER.unpack_from(data, 16)
        need(header[1] in (EM_BPF, EM_SBF), f"ELF machine {header[1]} is not Solana BPF/SBF")
        self.data = data
        self.machine = header[1]
        self.entry = header[3]
        self.e_flags = header[6]
        shoff, shentsize, shnum, shstr = header[5], header[10], header[11], header[12]
        need(shentsize >= SECTION_HEADER.size and shnum > 0 and shoff + shnum * shentsize <= len(data),
             "invalid section table")
        raw = [SECTION_HEADER.unpack_from(data, shoff + i * shentsize) for i in range(shnum)]
        need(shstr < shnum, "invalid section name table")
        names = self._slice(raw[shstr][4], raw[shstr][5])
        self.sections = []
        for row in raw:
            name = self._cstring(names, row[0])
            if row[1] != 8:  # SHT_NOBITS has no file contents.
                self._slice(row[4], row[5])
            self.sections.append(Section(name, row[1], row[2], row[3], row[4], row[5], row[6], row[9]))
        self.text = next((s for s in self.sections if s.name == ".text"), None)
        need(self.text is not None and self.text.size % 8 == 0, "missing or invalid .text")
        self.symbols = self._symbols()
        self.import_calls = self._import_calls()

    def _slice(self, offset: int, size: int) -> bytes:
        need(offset >= 0 and size >= 0 and offset + size <= len(self.data), "ELF section outside file")
        return self.data[offset:offset + size]

    @staticmethod
    def _cstring(data: bytes, offset: int) -> str:
        if offset >= len(data):
            return ""
        return data[offset:data.find(b"\0", offset) if b"\0" in data[offset:] else len(data)].decode("utf-8", "replace")

    def _symbols(self) -> list[Symbol]:
        found = []
        for section in self.sections:
            if section.kind not in (2, 11) or section.entsize < SYMBOL.size:
                continue
            need(section.link < len(self.sections), "invalid symbol string table")
            strings = self.section_data(self.sections[section.link])
            blob = self.section_data(section)
            for offset in range(0, len(blob) - SYMBOL.size + 1, section.entsize):
                name, info, _, index, value, size = SYMBOL.unpack_from(blob, offset)
                found.append(Symbol(self._cstring(strings, name), value, size, index, info & 15))
        return found

    def _import_calls(self) -> dict[int, str]:
        """Resolve SBF call relocations without treating them as local calls."""
        found = {}
        for section in self.sections:
            if section.kind != 9 or section.entsize < REL.size:
                continue
            need(section.link < len(self.sections), "invalid relocation symbol table")
            symbols = self.sections[section.link]
            need(symbols.kind in (2, 11) and symbols.entsize >= SYMBOL.size and
                 symbols.link < len(self.sections), "invalid relocation symbols")
            names = self.section_data(self.sections[symbols.link])
            symbol_data = self.section_data(symbols)
            relocation_data = self.section_data(section)
            for offset in range(0, len(relocation_data) - REL.size + 1, section.entsize):
                address, info = REL.unpack_from(relocation_data, offset)
                symbol_index, relocation_type = info >> 32, info & 0xFFFFFFFF
                if relocation_type != 10 or symbol_index * symbols.entsize + SYMBOL.size > len(symbol_data):
                    continue
                name_offset = SYMBOL.unpack_from(symbol_data, symbol_index * symbols.entsize)[0]
                name = self._cstring(names, name_offset)
                if name:
                    found[address] = name
        return found

    def section_data(self, section: Section) -> bytes:
        return self._slice(section.offset, section.size)


def executable_elf_prefix(raw: bytes) -> bytes:
    """Remove only zero-filled ProgramData allocation after the ELF file tables."""
    elf = ELF(raw)
    header = ELF_HEADER.unpack_from(raw, 16)
    phoff, shoff = header[4], header[5]
    phentsize, phnum = header[8], header[9]
    shentsize, shnum = header[10], header[11]
    end = max(64, shoff + shentsize * shnum)
    if phnum:
        need(phentsize >= 56 and phoff + phentsize * phnum <= len(raw),
             "invalid ELF program headers")
        for index in range(phnum):
            row = struct.unpack_from("<IIQQQQQQ", raw, phoff + index * phentsize)
            end = max(end, row[2] + row[5])
    for section in elf.sections:
        if section.kind != 8:
            end = max(end, section.offset + section.size)
    need(end <= len(raw) and not any(raw[end:]),
         "non-zero bytes follow the ELF file tables")
    return raw[:end]


def archived_program_elf(url: str, program_id: str, slot: int,
                         output: Path) -> dict:
    """Pin an executable program from the archive, including its loader metadata."""
    def read(pubkey: str) -> tuple[dict, bytes]:
        result = rpc(url, "getAccountInfo", [pubkey, {
            "slot": slot, "encoding": "base64", "commitment": "finalized",
        }])
        need(result["context"]["slot"] == slot and result["value"] is not None,
             f"archived account {pubkey} is unavailable at slot {slot}")
        value = result["value"]
        need(value["data"][1] == "base64", "archive did not return base64")
        return value, base64.b64decode(value["data"][0], validate=True)

    value, raw = read(program_id)
    need(value["executable"], f"{program_id} was not executable at slot {slot}")
    owner = value["owner"]
    deployment = None
    if owner == "BPFLoaderUpgradeab1e11111111111111111111111":
        need(len(raw) >= 36 and struct.unpack_from("<I", raw)[0] == 2,
             "invalid archived Program account")
        data_id = b58encode(raw[4:36])
        _, raw = read(data_id)
        need(len(raw) >= 45 and struct.unpack_from("<I", raw)[0] == 3,
             "invalid archived ProgramData account")
        deployment = struct.unpack_from("<Q", raw, 4)[0]
        raw = raw[45:]
    else:
        need(owner in {"BPFLoader2111111111111111111111111111111111",
                       "BPFLoader1111111111111111111111111111111111"},
             f"unsupported executable owner {owner}")
    elf = executable_elf_prefix(raw)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(elf)
    metadata = {"program_id": program_id, "owner": owner,
                "deployed_at_slot": deployment, "observed_slot": slot,
                "sha256": hashlib.sha256(elf).hexdigest(),
                "archive_match_mode": elf_match_mode(elf, raw)}
    output.with_suffix(output.suffix + ".json").write_text(
        json.dumps(metadata, indent=2) + "\n")
    return metadata


@dataclass
class Instruction:
    address: int
    opcode: int
    dst: int
    src: int
    offset: int
    imm: int
    slots: int = 1
    extra: int | None = None

    @property
    def target(self) -> int | None:
        cls, op = self.opcode & 7, self.opcode & 0xF0
        if cls in (5, 6) and (op in JMPS or op == 0):
            return self.address + 8 * (self.offset + 1)
        if self.opcode == 0x85 and self.src == 1:
            return self.address + 8 * (self.imm + 1)
        return None

    def signature(self) -> tuple:
        # Used to align instructions before counting operand differences.
        return (self.opcode, self.slots)

    def operands(self) -> tuple:
        return self.dst, self.src, self.offset, self.imm, self.extra


def instructions(elf: ELF) -> list[Instruction]:
    section = elf.text
    blob = elf.section_data(section)
    result = []
    offset = 0
    while offset + 8 <= len(blob):
        op, regs, displacement, imm = INSN.unpack_from(blob, offset)
        size, extra = 1, None
        if op == 0x18 and offset + 16 <= len(blob):
            _, _, _, extra = INSN.unpack_from(blob, offset + 8)
            size = 2
        result.append(Instruction(section.address + offset, op, regs & 15,
                                  regs >> 4, displacement, imm, size, extra))
        offset += 8 * size
    return result


def lift(ins: Instruction, names: dict[int, str], imports: dict[int, str] | None = None) -> str:
    op, cls = ins.opcode, ins.opcode & 7
    dst, src = f"r{ins.dst}", f"r{ins.src}"
    rhs = src if op & 8 else str(ins.imm)
    if op == 0x18:
        value = (ins.imm & 0xFFFFFFFF) | ((ins.extra or 0) & 0xFFFFFFFF) << 32
        return f"{dst} = 0x{value:016x}"
    if cls in (4, 7):
        operation = OPS.get(op & 0xF0)
        width = "u32" if cls == 4 else "u64"
        if operation == "mov":
            return f"{dst} = {rhs} as {width}"
        if operation == "neg":
            return f"{dst} = -{dst} as {width}"
        if operation == "end":
            return f"{dst} = endian_convert({dst}, {ins.imm})"
        if operation:
            return f"{dst} = {operation}({dst}, {rhs}) as {width}"
    size = SIZES.get(op & 0x18)
    if cls == 1 and size:
        return f"{dst} = load{size * 8}({src} {ins.offset:+d})"
    if cls == 2 and size:
        return f"store{size * 8}({dst} {ins.offset:+d}, {ins.imm})"
    if cls == 3 and size:
        return f"store{size * 8}({dst} {ins.offset:+d}, {src})"
    if cls in (5, 6):
        operation = op & 0xF0
        target = ins.target
        label = names.get(target, f"L_{target:x}") if target is not None else "?"
        if operation == 0x00:
            return f"goto {label}"
        if operation == 0x80:
            if op == 0x8D:
                return f"r0 = call_indirect({dst})"
            if imports and ins.address in imports:
                return f"r0 = {imports[ins.address]}(r1, r2, r3, r4, r5)"
            if ins.src == 1:
                return f"r0 = call {label}(r1, r2, r3, r4, r5)"
            return f"r0 = syscall(0x{ins.imm & 0xFFFFFFFF:08x}, r1, r2, r3, r4, r5)"
        if operation == 0x90:
            return "return r0"
        if operation in JMPS:
            relation = JMPS[operation]
            expr = f"({dst} & {rhs}) != 0" if relation == "&" else f"{dst} {relation} {rhs}"
            return f"if {expr}: goto {label}"
    return f"unknown(op=0x{op:02x}, dst={dst}, src={src}, off={ins.offset}, imm={ins.imm})"


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """Murmur3 x86 32-bit, the hash Solana uses for syscall symbol names."""
    c1, c2, mask = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    h = seed & mask

    def rotl(value: int, count: int) -> int:
        return ((value << count) | (value >> (32 - count))) & mask

    index, length = 0, len(data)
    while index + 4 <= length:
        k = int.from_bytes(data[index:index + 4], "little")
        index += 4
        k = (k * c1) & mask
        k = rotl(k, 15)
        k = (k * c2) & mask
        h = (h ^ k) & mask
        h = rotl(h, 13)
        h = (h * 5 + 0xE6546B64) & mask
    tail = data[index:]
    if tail:
        k = 0
        for position, byte in enumerate(tail):
            k |= byte << (8 * position)
        k = (k * c1) & mask
        k = rotl(k, 15)
        k = (k * c2) & mask
        h = (h ^ k) & mask
    h = (h ^ length) & mask
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & mask
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & mask
    h ^= h >> 16
    return h


SYSCALL_HASHES = {murmur3_32(name.encode()): name for name in SYSCALL_NAMES}


def sbpf_version(e_flags: int) -> dict:
    """Report the sBPF ISA version from the ELF e_flags with a modeling caveat."""
    return {"e_flags": e_flags,
            "version": SBPF_VERSIONS.get(e_flags, "unknown"),
            "fully_modeled": e_flags in FULLY_MODELED_SBPF}


def hashed_syscalls(elf: ELF, code: list[Instruction]) -> dict[int, str]:
    """Name static-syscall callsites (call imm = murmur hash, no relocation)."""
    start, end = elf.text.address, elf.text.address + elf.text.size
    found = {}
    for ins in code:
        if ins.opcode != 0x85 or ins.src != 0 or ins.address in elf.import_calls:
            continue
        target = ins.target
        # A local relative call lands inside .text; a static syscall does not.
        if target is not None and start <= target < end:
            continue
        name = SYSCALL_HASHES.get(ins.imm & 0xFFFFFFFF)
        if name:
            found[ins.address] = name
    return found


def find_functions(elf: ELF, code: list[Instruction]) -> list[dict]:
    start, end = elf.text.address, elf.text.address + elf.text.size
    funcs = {s.value: s.name for s in elf.symbols if s.kind == 2 and start <= s.value < end}
    if start <= elf.entry < end:
        funcs.setdefault(elf.entry, "entrypoint")
    calls = {ins.target for ins in code if ins.opcode == 0x85 and ins.src == 1
             and ins.address not in elf.import_calls}
    for address in calls:
        if address is not None and start <= address < end and (address - start) % 8 == 0:
            funcs.setdefault(address, f"sub_{address:x}")
    if not funcs:
        funcs[start] = f"sub_{start:x}"
    starts = sorted(funcs)
    result = []
    for i, address in enumerate(starts):
        stop = starts[i + 1] if i + 1 < len(starts) else end
        # The disjoint partition avoids giving a function the following symbol's bytes.
        body = [ins for ins in code if address <= ins.address < stop]
        if not body:
            continue
        result.append({"address": address, "end": stop, "name": funcs[address],
                       "instructions": body, "calls": sorted({ins.target for ins in body
                            if ins.opcode == 0x85 and ins.src == 1 and
                            ins.address not in elf.import_calls and ins.target in funcs})})
    return result


def strings(elf: ELF) -> list[dict]:
    result = []
    for section in elf.sections:
        if section.kind != 1 or not section.flags & 2 or section.flags & 4 or section.size == 0:
            continue
        blob = elf.section_data(section)
        for match in re.finditer(rb"[\x20-\x7e]{5,}", blob):
            result.append({"address": section.address + match.start(), "section": section.name,
                           "text": match.group().decode("ascii")[:300]})
    return result[:5000]


def reads_r0(ins: Instruction) -> bool:
    cls, operation = ins.opcode & 7, ins.opcode & 0xF0
    if cls in (4, 7):
        return (ins.dst == 0 and operation not in (0xB0, 0xD0)) or (ins.src == 0 and bool(ins.opcode & 8))
    if cls == 1:
        return ins.src == 0
    if cls == 2:
        return ins.dst == 0
    if cls == 3:
        return ins.dst == 0 or ins.src == 0
    if cls in (5, 6) and operation not in (0, 0x80, 0x90):
        return ins.dst == 0 or (ins.src == 0 and bool(ins.opcode & 8))
    return ins.opcode == 0x8D and ins.dst == 0


def writes_r0(ins: Instruction) -> bool:
    return ins.opcode == 0x85 or (ins.dst == 0 and
                                  (ins.opcode == 0x18 or (ins.opcode & 7) in (1, 4, 7)))


def solana_context(elf: ELF, code: list[Instruction]) -> dict:
    """Recover facts from the ELF without consulting any candidate source."""
    known = {b58decode(address): label for label, address in KNOWN_PROGRAM_IDS.items()}
    referenced = set()
    for ins in code:
        if ins.opcode == 0x18:
            referenced.add((ins.imm & 0xFFFFFFFF) | (((ins.extra or 0) & 0xFFFFFFFF) << 32))
    pubkeys = []
    used_labels = set()
    for address in sorted(referenced):
        section = next((section for section in elf.sections if section.kind == 1 and
                        section.flags & 2 and not section.flags & 4 and
                        section.address <= address and address + 32 <= section.address + section.size), None)
        if section:
            offset = address - section.address
            label = known.get(elf.section_data(section)[offset:offset + 32])
            if label:
                unique_label = label if label not in used_labels else f"{label}_{address:x}"
                used_labels.add(unique_label)
                pubkeys.append({"address": address, "name": unique_label})
    regions = find_functions(elf, code)
    functions = {item["address"] for item in regions
                 if any(ins.opcode == 0x95 for ins in item["instructions"])}
    return_uses = {}
    for index, ins in enumerate(code):
        if ins.opcode != 0x85 or ins.src != 1 or ins.address in elf.import_calls or ins.target not in functions:
            continue
        caller_end = next((item["end"] for item in regions
                           if item["address"] <= ins.address < item["end"]), elf.text.address + elf.text.size)
        for following in code[index + 1:index + 9]:
            if following.address >= caller_end:
                break
            if reads_r0(following):
                return_uses.setdefault(ins.target, []).append(ins.address)
                break
            if writes_r0(following) or (following.opcode & 7) in (5, 6):
                break
    return {"return_uses": [{"address": address, "caller": callers[0], "uses": len(callers)}
                             for address, callers in sorted(return_uses.items())],
            "known_program_ids": pubkeys,
            "import_calls": [{"address": address, "name": name}
                             for address, name in sorted(elf.import_calls.items())]}


def analyze(path: Path, output: Path) -> dict:
    binary = path.read_bytes()
    elf = ELF(binary)
    code = instructions(elf)
    funcs = find_functions(elf, code)
    names = {f["address"]: f["name"] for f in funcs}
    syscalls = hashed_syscalls(elf, code)
    imports = {**elf.import_calls, **syscalls}
    all_code = {ins.address for ins in code}
    bad_targets = sorted({ins.target for ins in code if ins.address not in imports
                          and ins.target is not None and ins.target not in all_code})
    discovered_strings = strings(elf)
    version = sbpf_version(elf.e_flags)
    warnings = [f"{len(bad_targets)} branch/call targets outside decoded .text"] if bad_targets else []
    if not version["fully_modeled"]:
        warnings.append(f"e_flags 0x{elf.e_flags:x} selects sBPF {version['version']};"
                        " a few ALU and call opcodes decode differently and are not fully modeled")
    result = {"input": str(path.resolve()), "sha256": hashlib.sha256(binary).hexdigest(),
            "bytes": len(binary), "elf_machine": elf.machine, "entrypoint": elf.entry,
              "sbpf": version,
              "text_address": elf.text.address, "text_bytes": elf.text.size,
              "instruction_count": len(code), "function_count": len(funcs),
              "functions": [], "strings": discovered_strings,
              "import_calls": [{"address": address, "name": name}
                               for address, name in sorted(elf.import_calls.items())],
              "syscall_imports": [{"address": address, "name": name}
                                  for address, name in sorted(syscalls.items())],
              "warnings": warnings}
    output.mkdir(parents=True, exist_ok=True)
    function_dir = output / "functions"
    function_dir.mkdir(exist_ok=True)
    for function in funcs:
        body = function["instructions"]
        targets = {ins.target for ins in body if ins.target in {x.address for x in body}}
        lines = [f"// {function['name']} at 0x{function['address']:x}",
                 "// Register-level lift. Types, account roles, and Rust source are not inferred."]
        for ins in body:
            if ins.address in targets:
                lines.append(f"L_{ins.address:x}:")
            lines.append(f"  /* 0x{ins.address:x} */ {lift(ins, names, imports)};")
        file = function_dir / f"{function['address']:08x}.txt"
        file.write_text("\n".join(lines) + "\n")
        references = []
        for ins in body:
            if ins.opcode != 0x18:
                continue
            value = (ins.imm & 0xFFFFFFFF) | ((ins.extra or 0) & 0xFFFFFFFF) << 32
            for item in discovered_strings:
                if item["address"] <= value < item["address"] + len(item["text"]):
                    references.append({"instruction": ins.address, "string": item["text"]})
                    break
        result["functions"].append({"address": function["address"], "end": function["end"],
             "name": function["name"], "instruction_count": len(body),
             "calls": function["calls"], "string_references": references[:100],
             "lift": str(file.relative_to(output))})
    covered = sum(f["end"] - f["address"] for f in funcs)
    result["function_partition_bytes"] = covered
    by_address = {f["address"]: f for f in result["functions"]}
    seen = set()
    order = []

    def visit(address: int) -> None:
        if address in seen:
            return
        seen.add(address)
        for callee in by_address[address]["calls"]:
            if callee in by_address:
                visit(callee)
        order.append(address)

    for address in by_address:
        visit(address)
    result["leaf_first_work_order"] = order
    (output / "analysis.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def decorate_decomp(source: str, context: dict, own_address: int | None = None) -> str:
    """Show ELF import names in exported pseudocode without changing the Ghidra project."""
    imported = []
    for item in context["import_calls"]:
        address, name = item["address"], item["name"]
        if own_address == address:
            continue
        placeholder = f"FUN_ram_{address:08x}"
        bound_name = f"{name}__reloc_{address:x}"
        if placeholder in source or bound_name in source:
            source = source.replace(placeholder, name).replace(bound_name, name)
            imported.append(name)
    for item in context["known_program_ids"]:
        source = source.replace(f"DAT_ram_{item['address']:08x}", item["name"])
    if imported:
        names = ", ".join(sorted(set(imported)))
        source = f"/* Solana imports: {names}. */\n" + source
    return source


def decompile(path: Path, output: Path, ghidra: Path, function: int | None,
              processor: str | None = None, keep_project: bool = False) -> dict:
    """Run Ghidra's C-like decompiler over an ELF, keeping original bytes intact."""
    binary = path.read_bytes()
    elf = ELF(binary)
    executable = ghidra / "support" / "analyzeHeadless"
    need(executable.is_file(), f"Ghidra analyzeHeadless missing: {executable}")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "project").mkdir(exist_ok=True)
    project_path = output / "project" / "soldecomp.gpr"
    if keep_project:
        need(not project_path.exists(), f"persistent project already exists: {project_path}; choose a fresh --out")
    import_path = path.resolve()
    patched = False
    if elf.machine == EM_SBF:
        # Ghidra's ELF loader selects eBPF for 247 but not Solana's 263.
        # This copy is only for analysis. The original remains the scoring target.
        copy = bytearray(binary)
        struct.pack_into("<H", copy, 18, EM_BPF)
        import_path = output / "analysis-only-em-bpf.so"
        import_path.write_bytes(copy)
        patched = True
    context = solana_context(elf, instructions(elf))
    context_path = output / "solana-context.json"
    context_path.write_text(json.dumps(context, indent=2) + "\n")
    hints_path = output / "solana-context.tsv"
    hint_lines = [f"return\t{item['address']:x}\t{item['caller']:x}"
                  for item in context["return_uses"]]
    hint_lines += [f"pubkey\t{item['address']:x}\t{item['name']}"
                   for item in context["known_program_ids"]]
    hints_path.write_text("\n".join(hint_lines) + "\n")
    imports_path = output / "solana-imports.tsv"
    imports_path.write_text("".join(f"{item['address']:x}\t{item['name']}\n"
                                    for item in context["import_calls"]))
    script = "ExportDecomp.java" if function is not None else "ExportAll.java"
    destination = output / (f"function-{function:x}.c" if function is not None else "functions")
    flow_path = output / "flow.json"
    script_args = [str(destination)]
    if function is not None:
        script_args.append(hex(function))
    command = [str(executable), str(output / "project"), "soldecomp", "-import",
               str(import_path)]
    if processor:
        command += ["-processor", processor]
    command += ["-scriptPath", str(Path(__file__).resolve().parent / "scripts"),
               "-postScript", "BindSolanaImports.java", str(imports_path),
               "-postScript", "ApplySolanaContext.java", str(hints_path),
               "-postScript", script, *script_args,
               "-postScript", "ExportFlow.java", str(flow_path),
               *([hex(function)] if function is not None else []),
               "-analysisTimeoutPerFile", "120",
               "-max-cpu", "4", *([] if keep_project else ["-deleteProject"])]
    home = Path(__file__).resolve().parent / ".toolchains" / "ghidra-home"
    home.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["JAVA_TOOL_OPTIONS"] = f"-Duser.home={home}"
    log = output / "ghidra.log"
    with log.open("w") as stream:
        completed = subprocess.run(command, env=environment, stdout=stream, stderr=subprocess.STDOUT,
                                   check=False)
    need(completed.returncode == 0, f"Ghidra failed; see {log}")
    import_run = re.search(r"BindSolanaImports: (\d+) signatures, (\d+) skipped", log.read_text())
    need(import_run is not None or (processor is not None and
         "BindSolanaImports: 0 signatures (processor does not use eBPF call stubs)" in log.read_text()),
         f"Solana import script did not finish; see {log}")
    context_run = re.search(r"ApplySolanaContext: (\d+) return signatures, (\d+) program ID labels",
                            log.read_text())
    need(context_run is not None, f"Solana context script did not finish; see {log}")
    need(destination.exists(), f"Ghidra produced no output; see {log}")
    need(flow_path.exists(), f"Ghidra produced no flow evidence; see {log}")
    if keep_project:
        need(project_path.exists(), f"Ghidra did not retain its project; see {log}")
    flow = json.loads(flow_path.read_text())
    need(flow["schema"] == 1, f"unsupported flow evidence: {flow_path}")
    flow_run = re.search(r"ExportFlow: (\d+) functions, (\d+) failed", log.read_text())
    need(flow_run is not None, f"Ghidra flow script did not finish; see {log}")
    symbols = {item["address"]: item["name"] for item in context["known_program_ids"]}
    def label_constants(value: dict | list) -> None:
        if isinstance(value, list):
            for child in value:
                label_constants(child)
        elif isinstance(value, dict):
            if value.get("kind") == "constant":
                name = symbols.get(int(value["value"], 16))
                if name:
                    value["symbol"] = name
            for child in value.values():
                if isinstance(child, (dict, list)):
                    label_constants(child)
    label_constants(flow["functions"])
    digest = hashlib.sha256(binary).hexdigest()
    snapshot_path = path.with_suffix(path.suffix + ".json")
    snapshot = json.loads(snapshot_path.read_text()) if snapshot_path.is_file() else None
    if snapshot and snapshot.get("sha256") == digest:
        flow["program_snapshot"] = {key: snapshot.get(key) for key in
                                    ("program_id", "owner", "observed_slot", "deployed_at_slot")}
    if snapshot and snapshot.get("sha256") == digest and \
            snapshot.get("owner") == "BPFLoader1111111111111111111111111111111111":
        flow["input_abi"] = "deprecated_loader_unmodeled"
    else:
        annotate_solana_input(flow, elf.entry)
        flow["input_abi"] = "standard_aligned_assumed"
    flow["input_sha256"] = digest
    flow["entrypoint"] = hex(elf.entry)
    flow["known_program_ids"] = context["known_program_ids"]
    flow_path.write_text(json.dumps(flow, separators=(",", ":")) + "\n")
    if function is not None:
        exported = destination.read_text()
        need("\nerror=" not in exported and "\nfunction=" in exported,
             f"Ghidra could not decompile function 0x{function:x}; see {destination}")
        destination.write_text(decorate_decomp(exported, context, function))
        count, failed = 1, 0
    else:
        index = destination / "index.tsv"
        rows = index.read_text().splitlines()[1:]
        count = sum(line.endswith("\tok") for line in rows)
        failed = sum(line.endswith("\tfailed") for line in rows)
        for file in destination.glob("*.c"):
            file.write_text(decorate_decomp(file.read_text(), context, int(file.stem, 16)))
    result = {"input": str(path.resolve()), "sha256": hashlib.sha256(binary).hexdigest(),
              "elf_machine": elf.machine, "analysis_header_patched": patched,
              "requested_processor": processor,
              "decompiled_functions": count, "failed_functions": failed,
              "context": str(context_path),
              "inferred_return_functions": len(context["return_uses"]),
              "applied_return_signatures": int(context_run.group(1)),
              "applied_import_signatures": int(import_run.group(1)) if import_run else 0,
              "known_program_ids": len(context["known_program_ids"]),
              "named_import_calls": len(context["import_calls"]),
              "output": str(destination), "flow": str(flow_path),
              "flow_functions": sum(item["status"] == "ok" for item in flow["functions"]),
              "flow_failed_functions": int(flow_run.group(2)),
              "flow_events": sum(len(item["events"]) for item in flow["functions"]),
              "log": str(log),
              "project": str(project_path) if keep_project else None,
              "project_binary": str(import_path) if keep_project else None,
              "warning": "Ghidra output is C-like pseudocode, not reconstructed Rust."
                         + (" EM_SBF was relabeled EM_BPF only in the analysis copy."
                            if patched else "")}
    (output / "decompile.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def input_pointer_offset(value: dict, parameter: int = 0) -> int | None:
    """Recognize a direct pointer into the Solana entrypoint input buffer."""
    if value.get("kind") == "parameter" and value.get("index") == parameter:
        return 0
    if value.get("kind") != "operation":
        return None
    op, args = value["op"], value["inputs"]
    if op in ("COPY", "CAST", "INT_ZEXT") and args:
        return input_pointer_offset(args[0], parameter)
    if op not in ("PTRADD", "PTRSUB", "INT_ADD", "INT_SUB") or len(args) < 2:
        return None
    base = input_pointer_offset(args[0], parameter)
    if base is None:
        return None
    if args[1].get("kind") != "constant":
        return None
    displacement = int(args[1]["value"], 16)
    if op == "PTRADD":
        if len(args) < 3 or args[2].get("kind") != "constant":
            return None
        displacement *= int(args[2]["value"], 16)
    if op == "INT_SUB":
        displacement = -displacement
    offset = base + displacement
    return offset if 0 <= offset < 1 << 32 else None


def solana_input_field(offset: int | None) -> str | None:
    """Name only fixed fields in the standard aligned input ABI."""
    if offset is None:
        return None
    if 0 <= offset < 8:
        return "account_count" + (f"+{offset}" if offset else "")
    fields = ((8, 9, "duplicate_marker"), (9, 10, "is_signer"),
              (10, 11, "is_writable"), (11, 12, "executable"),
              (12, 16, "original_data_len"), (16, 48, "key"),
              (48, 80, "owner"), (80, 88, "lamports"),
              (88, 96, "data_len"))
    for start, end, name in fields:
        if start <= offset < end:
            suffix = f"+{offset - start}" if offset > start else ""
            return f"account_0.{name}{suffix}" + ("" if name == "duplicate_marker"
                                                     else "_if_unique")
    return None


def annotate_solana_input(flow: dict, entrypoint: int) -> None:
    """Follow direct input-buffer pointers through calls and label fixed ABI fields."""
    functions = {int(item["address"], 16): item for item in flow["functions"]}
    pending = [(entrypoint, 0, 0)]
    seen = set()
    while pending:
        address, parameter, base = pending.pop()
        if (address, parameter, base) in seen or address not in functions:
            continue
        seen.add((address, parameter, base))
        if len(seen) > 1024:
            flow["input_analysis_truncated"] = True
            break
        for operation in functions[address]["events"]:
            if operation["kind"] in ("load", "store") and operation["inputs"]:
                relative = input_pointer_offset(operation["inputs"][0], parameter)
                offset = base + relative if relative is not None else None
                field = solana_input_field(offset)
                if field:
                    candidate = {"offset": offset, "field": field,
                                 "via_parameter": parameter}
                    operation.setdefault("solana_input", [])
                    if isinstance(operation["solana_input"], dict):
                        operation["solana_input"] = [operation["solana_input"]]
                    if candidate not in operation["solana_input"]:
                        operation["solana_input"].append(candidate)
            if operation["kind"] not in ("call", "callind") or not operation.get("target"):
                continue
            target = int(operation["target"], 16)
            if target not in functions:
                continue
            for index, argument in enumerate(operation["inputs"]):
                relative = input_pointer_offset(argument, parameter)
                if relative is not None and base + relative < 1 << 32:
                    pending.append((target, index, base + relative))
    flow["input_pointer_contexts"] = len(seen)


def trace_flow(path: Path, function: int | None, event: int | None,
               callee: str | None, kind: str | None, op: str | None,
               parameter: int | None,
               caller: int | None, via: list[int], include_callers: bool,
               limit: int) -> dict:
    """Find P-code evidence and the callers that supply a selected function's inputs."""
    need(limit > 0, "--limit must be positive")
    need(any(value is not None for value in (function, event, callee, kind, op)),
         "select --function, --event, --callee, --kind, or --op")
    need(parameter is None or (function is not None and parameter >= 0),
         "--parameter needs --function and a nonnegative index")
    need(caller is None or function is not None, "--caller needs --function")
    need(caller is None or include_callers, "--caller cannot be used with --no-callers")
    need(not via or (function is not None and event is not None and caller is None),
         "--via needs --function and --event, without --caller")
    def uses_parameter(value: dict | list) -> bool:
        if isinstance(value, list):
            return any(uses_parameter(child) for child in value)
        if value.get("kind") == "parameter" and value["index"] == parameter:
            return True
        return any(uses_parameter(child) for child in value.values()
                   if isinstance(child, (dict, list)))
    def bind_parameters(value: dict | list, arguments: list) -> dict | list:
        if isinstance(value, list):
            return [bind_parameters(child, arguments) for child in value]
        if value.get("kind") == "parameter":
            index = value["index"]
            if index < len(arguments):
                return arguments[index]
        return {key: bind_parameters(child, arguments) if isinstance(child, (dict, list))
                else child for key, child in value.items()}
    flow = json.loads(path.read_text())
    need(flow.get("schema") == 1, "unsupported flow evidence schema")
    functions = flow["functions"]
    selected = []
    for item in functions:
        if function is not None and int(item["address"], 16) != function:
            continue
        for operation in item["events"]:
            if event is not None and int(operation["address"], 16) != event:
                continue
            if callee is not None and operation.get("callee") != callee:
                continue
            if kind is not None and operation["kind"] != kind:
                continue
            if op is not None and operation.get("op") != op:
                continue
            if parameter is not None and not uses_parameter(operation["inputs"]):
                continue
            selected.append({"function": item["address"], "function_name": item["name"],
                             **operation})
    result = {"flow": str(path.resolve()), "input_sha256": flow.get("input_sha256"),
              "matches": len(selected), "events": selected[:limit]}
    if via:
        need(len(selected) == 1, "--via needs exactly one matching event")
        by_address = {int(item["address"], 16): item for item in functions}
        paths = [{"calls": [], "inputs": selected[0]["inputs"]}]
        target = function
        for origin in via:
            need(origin in by_address, f"caller function 0x{origin:x} not in flow")
            candidates = [operation for operation in by_address[origin]["events"]
                          if operation["kind"] in ("call", "callind") and
                          operation.get("target") and int(operation["target"], 16) == target]
            need(candidates, f"no call from 0x{origin:x} to 0x{target:x}")
            next_paths = []
            for path_item in paths:
                for operation in candidates:
                    next_paths.append({
                        "calls": path_item["calls"] + [{"from": hex(origin),
                                                         "at": operation["address"],
                                                         "to": hex(target)}],
                        "inputs": bind_parameters(path_item["inputs"], operation["inputs"]),
                    })
            if len(next_paths) > limit:
                result["paths_truncated_at"] = limit
            paths = next_paths[:limit]
            target = origin
        result["origin_function"] = hex(target)
        result["paths"] = paths
    if function is not None and include_callers and not via:
        callers = []
        for item in functions:
            if caller is not None and int(item["address"], 16) != caller:
                continue
            for operation in item["events"]:
                if operation["kind"] in ("call", "callind") and \
                        operation.get("target") and int(operation["target"], 16) == function:
                    callsite = {"function": item["address"], "function_name": item["name"],
                                "address": operation["address"],
                                "argument_sources": operation["inputs"]}
                    if event is not None and len(selected) == 1:
                        callsite["event_inputs_at_caller"] = bind_parameters(
                            selected[0]["inputs"], operation["inputs"])
                    callers.append(callsite)
        result["callers"] = callers[:limit]
        result["caller_count"] = len(callers)
    if len(selected) > limit or result.get("caller_count", 0) > limit:
        result["truncated_at"] = limit
    return result


def evidence_packet(flow_path: Path, function: int, event: int | None,
                    max_events: int, output: Path) -> dict:
    """Save a bounded, version-pinned function packet for an agent review round."""
    need(max_events > 0, "--max-events must be positive")
    flow = json.loads(flow_path.read_text())
    need(flow.get("schema") == 1, "unsupported flow evidence schema")
    item = next((row for row in flow["functions"]
                 if int(row["address"], 16) == function), None)
    need(item is not None, f"function 0x{function:x} not in flow evidence")
    source_paths = [flow_path.parent / f"function-{function:x}.c",
                    flow_path.parent / "functions" / f"{function:016x}.c"]
    source_path = next((path for path in source_paths if path.is_file()), None)
    need(source_path is not None, f"decompiled function 0x{function:x} missing beside {flow_path}")
    trace = trace_flow(flow_path, function, event, None, None, None, None,
                       None, [], True, max_events)
    need(trace["matches"] > 0, f"event 0x{event:x} not found in function 0x{function:x}"
         if event is not None else f"function 0x{function:x} has no flow events")
    packet = {"schema": 1, "purpose": "bounded function evidence for Rust reconstruction or bug review",
              "input_sha256": flow.get("input_sha256"),
              "program_snapshot": flow.get("program_snapshot"),
              "input_abi": flow.get("input_abi"),
              "entrypoint": flow.get("entrypoint"),
              "function": {"address": item["address"], "name": item["name"],
                           "status": item["status"], "event_count": len(item["events"])},
              "decompiler": {"kind": "Ghidra C-like pseudocode",
                             "path": str(source_path.resolve()),
                             "text": source_path.read_text()},
              "trace": trace,
              "caveats": ["Account roles and Rust types are hypotheses until independently checked.",
                          "A score improvement does not prove equivalent behavior."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(packet, indent=2) + "\n")
    return {"packet": str(output.resolve()), "input_sha256": packet["input_sha256"],
            "function": item["address"], "selected_events": len(trace["events"]),
            "matching_events": trace["matches"],
            "caller_count": trace.get("caller_count", 0),
            "truncated": "truncated_at" in trace}


def build_candidate(project: Path, output: Path, toolchain: Path, target: Path | None) -> dict:
    """Build a Rust Solana cdylib with an explicitly selected platform-tools release."""
    project, output, toolchain = project.resolve(), output.resolve(), toolchain.resolve()
    manifest = project / "Cargo.toml"
    need(manifest.is_file(), f"Cargo.toml missing: {manifest}")
    package = tomllib.loads(manifest.read_text())
    library = package.get("lib", {}).get("name") or package.get("package", {}).get("name", "")
    need(bool(library), "cannot infer Rust library name from Cargo.toml")
    library = library.replace("-", "_")
    root = Path(__file__).resolve().parent
    cargo_home = root / ".toolchains" / "cargo"
    rustup_home = root / ".toolchains" / "rustup"
    # Cargo itself affects the final binary here; use the one bundled with the
    # selected platform-tools release, as the reference build script does.
    cargo = toolchain / "rust" / "bin" / "cargo"
    rustc = toolchain / "rust" / "bin" / "rustc"
    clang = toolchain / "llvm" / "bin" / "clang"
    ar = toolchain / "llvm" / "bin" / "llvm-ar"
    objcopy = toolchain / "llvm" / "bin" / "llvm-objcopy"
    for item in (cargo, rustc, clang, ar, objcopy):
        need(item.is_file(), f"build tool missing: {item}")
    output.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update({"CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home),
                        "RUSTC": str(rustc), "CC": str(clang), "AR": str(ar),
                        "CARGO_TARGET_SBPF_SOLANA_SOLANA_RUSTFLAGS":
                        "-C lto=no -C opt-level=3 -Zremap-cwd-prefix=",
                        "PATH": f"{rustc.parent}:{clang.parent}:{cargo.parent}:{environment.get('PATH', '')}"})
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_INCREMENTAL"):
        environment.pop(name, None)
    log = output.with_suffix(output.suffix + ".build.log")
    with log.open("w") as stream:
        completed = subprocess.run([str(cargo), "build", "--release", "--locked", "--target",
                                    "sbpf-solana-solana"], cwd=project, env=environment,
                                   stdout=stream, stderr=subprocess.STDOUT, check=False)
    need(completed.returncode == 0, f"Cargo build failed; see {log}")
    unstripped = project / "target" / "sbpf-solana-solana" / "release" / f"{library}.so"
    need(unstripped.is_file(), f"compiled ELF missing: {unstripped}")
    with log.open("a") as stream:
        stripped = subprocess.run([str(objcopy), "--strip-all", str(unstripped), str(output)],
                                  stdout=stream, stderr=subprocess.STDOUT, check=False)
    need(stripped.returncode == 0 and output.is_file(), f"ELF strip failed; see {log}")
    result = {"project": str(project), "candidate": str(output),
              "toolchain": str(toolchain), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
              "bytes": output.stat().st_size, "build_log": str(log)}
    if target:
        report = compare(target, output)
        report_path = output.with_suffix(output.suffix + ".score.json")
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        result.update({"target": str(target.resolve()), "binary_exact": report["binary_exact"],
                       "binary_diff_bytes": report["binary_diff_bytes"],
                       "function_score": report["total_score"], "score_report": str(report_path)})
    output.with_suffix(output.suffix + ".build.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def score_pair(target: list[Instruction], candidate: list[Instruction]) -> dict:
    matcher = difflib.SequenceMatcher(None, [x.signature() for x in target],
                                      [x.signature() for x in candidate], autojunk=False)
    score = extra = operands = stack = 0
    for tag, a, b, c, d in matcher.get_opcodes():
        if tag in ("insert", "delete"):
            extra += (b - a) + (d - c)
        elif tag == "replace":
            overlap = min(b - a, d - c)
            extra += abs((b - a) - (d - c))
            for index in range(overlap):
                if target[a + index].opcode != candidate[c + index].opcode:
                    score += 60
                elif target[a + index].operands() != candidate[c + index].operands():
                    operands += 1
        else:
            for left, right in zip(target[a:b], candidate[c:d]):
                if left.operands() != right.operands():
                    operands += 1
                    if left.offset != right.offset and (left.opcode & 7) in (1, 2, 3):
                        stack += abs(left.offset - right.offset)
    score += 100 * extra + 5 * operands + stack
    return {"score": score, "extra_or_missing": extra, "operand_changes": operands,
            "memory_offset_distance": stack, "exact": len(target) == len(candidate) and
            all((a.opcode, a.operands()) == (b.opcode, b.operands())
                for a, b in zip(target, candidate))}


def rust_crate_name(symbol: str) -> str | None:
    """Read the first crate component from a legacy Rust-mangled symbol."""
    match = re.match(r"^_ZN(\d+)", symbol)
    if not match:
        return None
    start = match.end()
    size = int(match.group(1))
    return symbol[start:start + size] if len(symbol) >= start + size else None


def compare(target_path: Path, candidate_path: Path, mapping: Path | None = None,
            symbol_elf: Path | None = None, project_crates: list[str] | None = None) -> dict:
    target_bytes, candidate_bytes = target_path.read_bytes(), candidate_path.read_bytes()
    target_elf, candidate_elf = ELF(target_bytes), ELF(candidate_bytes)
    target_code, candidate_code = instructions(target_elf), instructions(candidate_elf)
    target_funcs, candidate_funcs = find_functions(target_elf, target_code), find_functions(candidate_elf, candidate_code)
    candidate_by = {f["address"]: f for f in candidate_funcs}
    names = {f["name"]: f for f in candidate_funcs if not f["name"].startswith("sub_")}
    annotated_symbols = {}
    selected_crates = {name.replace("-", "_") for name in (project_crates or [])}
    if symbol_elf:
        need(selected_crates, "--symbols-from requires at least one --project-crate")
        unstripped = ELF(symbol_elf.read_bytes())
        need(unstripped.text.address == candidate_elf.text.address and
             unstripped.section_data(unstripped.text) == candidate_elf.section_data(candidate_elf.text),
             "--symbols-from .text does not match the candidate ELF")
        for symbol in unstripped.symbols:
            if symbol.kind == 2 and symbol.name:
                annotated_symbols[symbol.value] = symbol.name
    explicit = json.loads(mapping.read_text()) if mapping else {}
    results = []
    unmatched = []
    for index, function in enumerate(target_funcs):
        address = function["address"]
        partner = None
        method = None
        if str(address) in explicit or f"0x{address:x}" in explicit:
            value = explicit.get(str(address), explicit.get(f"0x{address:x}"))
            partner = candidate_by.get(int(value, 0) if isinstance(value, str) else value)
            method = "explicit"
        elif function["name"] in names:
            partner = names[function["name"]]
            method = "symbol"
        elif len(target_funcs) == len(candidate_funcs):
            partner = candidate_funcs[index]
            method = "ordinal"
        if partner is None:
            unmatched.append(address)
            continue
        result = score_pair(function["instructions"], partner["instructions"])
        row = {"target": address, "candidate": partner["address"], "name": function["name"],
               "matching": method, **result}
        if symbol_elf:
            symbol_name = annotated_symbols.get(partner["address"])
            crate = rust_crate_name(symbol_name) if symbol_name else None
            row.update({"candidate_symbol": symbol_name, "candidate_crate": crate,
                        "origin": "project" if crate in selected_crates else
                                  "library" if crate else "unknown"})
        results.append(row)
    candidate_sections = {section.name: candidate_elf.section_data(section)
                          for section in candidate_elf.sections if section.kind != 8 and section.name}
    section_differences = {}
    for section in target_elf.sections:
        if section.kind == 8 or not section.name or section.name not in candidate_sections:
            continue
        left, right = target_elf.section_data(section), candidate_sections[section.name]
        if left != right:
            section_differences[section.name] = sum(a != b for a, b in zip(left, right)) + abs(len(left) - len(right))
    report = {"target_sha256": hashlib.sha256(target_bytes).hexdigest(),
            "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            "binary_exact": target_bytes == candidate_bytes,
            "binary_diff_bytes": sum(a != b for a, b in zip(target_bytes, candidate_bytes))
                                 + abs(len(target_bytes) - len(candidate_bytes)),
            "section_diff_bytes": section_differences,
            "target_functions": len(target_funcs), "candidate_functions": len(candidate_funcs),
            "unmatched": unmatched, "total_score": sum(x["score"] for x in results),
            "functions": results,
            "warning": "Ordinal matches are provisional. Use --map for stripped binaries with changed function order."}
    if symbol_elf:
        report["origin_summary"] = {origin: {
            "functions": sum(item["origin"] == origin for item in results),
            "exact": sum(item["origin"] == origin and item["exact"] for item in results),
            "score": sum(item["score"] for item in results if item["origin"] == origin)}
            for origin in ("project", "library", "unknown")}
        report["origin_warning"] = ("Origin uses legacy Rust symbol prefixes from the candidate build. "
                                    "Unknown symbols and provisional ordinal matches need review; "
                                    "this does not reproduce OtterSec's library matching.")
    return report


FORBIDDEN = [
    ("inline assembly", re.compile(r"\b(?:asm|global_asm)!\s*\(")),
    ("black_box", re.compile(r"\bblack_box\s*\(")),
    ("volatile memory", re.compile(r"\b(?:read_volatile|write_volatile)\s*\(")),
    ("transmute", re.compile(r"\btransmute(?:_copy)?\s*(?:::<[^>]+>)?\s*\(")),
]


def scan_source(directory: Path) -> list[dict]:
    findings = []
    for path in sorted(directory.rglob("*.rs")):
        source = path.read_text(errors="replace")
        for number, line in enumerate(source.splitlines(), 1):
            code = line.split("//", 1)[0]
            for label, pattern in FORBIDDEN:
                if pattern.search(code):
                    findings.append({"file": str(path), "line": number, "kind": label})
            if "#[no_mangle]" in code:
                # Export exceptions must be inspected because names can be on later lines.
                window = "\n".join(source.splitlines()[number:number + 5])
                if not re.search(r"\bfn\s+(?:entrypoint|custom_panic)\b", window):
                    findings.append({"file": str(path), "line": number, "kind": "internal no_mangle"})
    return findings


def judge(target: Path, candidate: Path, baseline: Path | None, source: Path | None,
          mapping: Path | None, baseline_mapping: Path | None = None) -> dict:
    current = compare(target, candidate, mapping)
    previous = compare(target, baseline, baseline_mapping or mapping) if baseline else None
    regression = []
    if previous:
        before = {x["target"]: x["score"] for x in previous["functions"]}
        for item in current["functions"]:
            if item["target"] in before and item["score"] > before[item["target"]]:
                regression.append({"target": item["target"], "before": before[item["target"]],
                                   "after": item["score"]})
    banned = scan_source(source) if source else []
    provisional = any(item["matching"] == "ordinal" for item in current["functions"])
    passed = not banned and not current["unmatched"] and not regression
    if previous:
        passed = passed and (current["total_score"] < previous["total_score"]
                             or current["binary_exact"])
    else:
        passed = passed and current["binary_exact"]
    passed = passed and (not provisional or current["binary_exact"])
    return {"passed": passed, "current": current, "baseline_score": previous["total_score"] if previous else None,
            "regressions": regression, "forbidden_source": banned,
            "provisional_function_mapping": provisional,
            "note": "Score is an alignment heuristic, not the OtterSec scorer. Binary exactness is SHA-256 equality."}



def serialize_route_context_sysvar(transaction: dict, outer_index: int) -> str:
    """Serialize original outer instructions with the selected parent at index zero.

    LiteSVM runs the selected CPI as a top-level instruction, so its runtime
    writes index zero into the instructions sysvar. Moving the parent route to
    index zero preserves its program ID, accounts, and data for route checks.
    """
    message = transaction["transaction"]["message"]
    static = message["accountKeys"]
    loaded = (transaction.get("meta") or {}).get("loadedAddresses") or {}
    writable_loaded = loaded.get("writable", [])
    keys = static + writable_loaded + loaded.get("readonly", [])
    instructions = message["instructions"]
    need(0 <= outer_index < len(instructions) and len(instructions) <= 65535,
         "invalid outer instruction index or count")
    header = message["header"]
    required = header["numRequiredSignatures"]
    writable_signed = required - header["numReadonlySignedAccounts"]
    writable_static = len(static) - header["numReadonlyUnsignedAccounts"]
    ordered = [instructions[outer_index]] + [item for index, item in enumerate(instructions)
                                                if index != outer_index]
    data = bytearray(struct.pack("<H", len(ordered)))
    data.extend(b"\0" * (2 * len(ordered)))
    for index, item in enumerate(ordered):
        need(len(data) <= 65535, "instructions sysvar offset exceeds u16")
        struct.pack_into("<H", data, 2 + 2 * index, len(data))
        accounts = item["accounts"]
        need(len(accounts) <= 65535, "too many instruction accounts")
        data.extend(struct.pack("<H", len(accounts)))
        for account_index in accounts:
            need(0 <= account_index < len(keys),
                 "instruction account index is out of range")
            signer = account_index < required
            writable = (account_index < writable_signed if signer else
                        account_index < writable_static if account_index < len(static) else
                        account_index < len(static) + len(writable_loaded))
            data.append(int(signer) | (int(writable) << 1))
            account_key = b58decode(keys[account_index])
            need(len(account_key) == 32, "invalid instruction account pubkey")
            data.extend(account_key)
        program_index = item["programIdIndex"]
        need(0 <= program_index < len(keys), "invalid instruction program index")
        program_key = b58decode(keys[program_index])
        need(len(program_key) == 32, "invalid instruction program pubkey")
        data.extend(program_key)
        instruction_data = b58decode(item["data"]) if item["data"] else b""
        need(len(instruction_data) <= 65535, "instruction data exceeds u16")
        data.extend(struct.pack("<H", len(instruction_data)))
        data.extend(instruction_data)
    data.extend(b"\0\0")
    return base64.b64encode(data).decode()


def capture_transaction(signature: str, elf_path: Path, instruction_index: int,
                        inner_index: int | None, signer_overrides: list[str],
                        url: str, output: Path, full_transaction: bool = False) -> dict:
    """Capture one historical instruction with live account bytes for local replay.

    Standard RPC does not provide historical account data, so this fixture is
    deliberately marked state_exact=false and retains both observation slots.
    """
    need(len(b58decode(signature)) == 64, "signature must decode to 64 bytes")
    need(instruction_index >= 0, "instruction index must be non-negative")
    elf = elf_path.read_bytes()
    need(elf.startswith(b"\x7fELF"), "--elf must be a Solana ELF")
    transaction = rpc(url, "getTransaction", [signature, {
        "encoding": "json", "commitment": "finalized",
        "maxSupportedTransactionVersion": 1,
    }])
    need(transaction is not None, "transaction not available from this RPC")
    message = transaction["transaction"]["message"]
    static = message["accountKeys"]
    need(all(isinstance(key, str) for key in static),
         "RPC returned parsed account keys instead of raw JSON")
    loaded = (transaction.get("meta") or {}).get("loadedAddresses") or {}
    writable_loaded = loaded.get("writable", [])
    readonly_loaded = loaded.get("readonly", [])
    keys = static + writable_loaded + readonly_loaded
    instructions = message["instructions"]
    need(instruction_index < len(instructions),
         f"instruction index must be below {len(instructions)}")
    selected = instructions[instruction_index]
    if inner_index is not None:
        need(inner_index >= 0, "inner instruction index must be non-negative")
        groups = [group for group in ((transaction.get("meta") or {}).get("innerInstructions") or [])
                  if group["index"] == instruction_index]
        need(len(groups) == 1, "inner instructions not available for this outer instruction")
        need(inner_index < len(groups[0]["instructions"]),
             f"inner index must be below {len(groups[0]['instructions'])}")
        selected = groups[0]["instructions"][inner_index]
    program_index = selected["programIdIndex"]
    need(0 <= program_index < len(keys), "invalid program ID index")
    program_id = keys[program_index]
    header = message["header"]
    required = header["numRequiredSignatures"]
    readonly_signed = header["numReadonlySignedAccounts"]
    readonly_unsigned = header["numReadonlyUnsignedAccounts"]

    def flags(index: int) -> tuple[bool, bool]:
        if index < len(static):
            signer = index < required
            writable = (index < required - readonly_signed if signer else
                        index < len(static) - readonly_unsigned)
            return signer, writable
        return False, index < len(static) + len(writable_loaded)

    metas = []
    for index in selected["accounts"]:
        need(isinstance(index, int) and 0 <= index < len(keys),
             "invalid instruction account index")
        signer, writable = flags(index)
        metas.append({"pubkey": keys[index], "is_signer": signer,
                      "is_writable": writable})
    for override in signer_overrides:
        need(len(b58decode(override)) == 32, "signer override must be a pubkey")
        need(any(meta["pubkey"] == override for meta in metas),
             f"signer override {override} is not in the selected instruction")
        for meta in metas:
            if meta["pubkey"] == override:
                meta["is_signer"] = True
    payer = static[0]
    lookup_keys = [row["accountKey"] for row in message.get("addressTableLookups") or []]
    addresses = list(dict.fromkeys([payer] + (keys + lookup_keys if full_transaction else
                                            [meta["pubkey"] for meta in metas])))
    accounts = {}
    executable_owners = {}
    observed_slots = []
    notes = []
    for offset in range(0, len(addresses), 100):
        chunk = addresses[offset:offset + 100]
        response = rpc(url, "getMultipleAccounts", [chunk, {
            "encoding": "base64", "commitment": "finalized",
        }])
        observed_slots.append(response["context"]["slot"])
        need(len(response["value"]) == len(chunk),
             "RPC account result length does not match request")
        for address, value in zip(chunk, response["value"]):
            if value is None:
                accounts[address] = None
                notes.append(f"{address} is absent at observation slot")
                continue
            need(value["data"][1] == "base64", "RPC did not return base64")
            raw = base64.b64decode(value["data"][0], validate=True)
            need(value.get("space", len(raw)) == len(raw),
                 f"RPC account {address} space/data length mismatch")
            if value["executable"]:
                executable_owners[address] = value["owner"]
                accounts[address] = None
                notes.append(f"Executable account {address} was not copied; ensure the runtime has it if used by CPI")
                continue
            accounts[address] = {
                "lamports": value["lamports"], "owner": value["owner"],
                "executable": False, "rent_epoch": value["rentEpoch"],
                "data_base64": base64.b64encode(raw).decode(),
            }
    need(len(set(observed_slots)) == 1,
         "account batches came from different slots; retry capture")
    transaction_base64 = None
    extra_programs = []
    if full_transaction:
        encoded = rpc(url, "getTransaction", [signature, {
            "encoding": "base64", "commitment": "finalized",
            "maxSupportedTransactionVersion": 1,
        }])
        need(encoded is not None and encoded["slot"] == transaction["slot"] and
             encoded["transaction"][1] == "base64",
             "raw transaction is unavailable or differs from parsed transaction")
        transaction_base64 = encoded["transaction"][0]
        all_instructions = list(instructions)
        for group in (transaction.get("meta") or {}).get("innerInstructions") or []:
            all_instructions.extend(group["instructions"])
        invoked = list(dict.fromkeys(keys[item["programIdIndex"]]
                                         for item in all_instructions))
        for invoked_id in invoked:
            if invoked_id == program_id:
                continue
            owner = executable_owners.get(invoked_id)
            if owner is None:
                notes.append(f"Invoked program {invoked_id} has no executable snapshot; local runtime must provide it")
                continue
            if owner not in {"BPFLoaderUpgradeab1e11111111111111111111111",
                             "BPFLoader2111111111111111111111111111111111",
                             "BPFLoader1111111111111111111111111111111111"}:
                continue
            extra_path = output.parent / "programs" / f"{invoked_id}.so"
            extra_meta = fetch(invoked_id, url, extra_path)
            extra_programs.append({"id": invoked_id,
                                   "elf": os.path.relpath(extra_path.resolve(), output.parent.resolve()),
                                   "sha256": extra_meta["sha256"],
                                   "loader": extra_meta["owner"],
                                   "deployed_at_slot": extra_meta["deployed_at_slot"],
                                   "version_observed_slot": extra_meta["programdata_observed_slot"]})
    metadata_path = elf_path.with_suffix(elf_path.suffix + ".json")
    program_meta = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
    if program_meta.get("program_id"):
        need(program_meta["program_id"] == program_id,
             "ELF sidecar program ID differs from selected instruction")
    deployed_at_slot = program_meta.get("deployed_at_slot")
    if deployed_at_slot is not None and transaction["slot"] < deployed_at_slot:
        raise ValueError("selected transaction predates the ELF deployment slot")
    # A later live ProgramData account can prove the ELF was installed at the
    # transaction slot when its deployment slot has not advanced since then.
    live_info, live_program_slot = account(url, program_id)
    live_owner = live_info["owner"]
    live_raw = live_info["raw"]
    live_deployed_at = None
    live_data_slot = live_program_slot
    if live_owner == "BPFLoaderUpgradeab1e11111111111111111111111":
        need(len(live_raw) >= 36 and struct.unpack_from("<I", live_raw)[0] == 2,
             "invalid live Program account")
        live_programdata = b58encode(live_raw[4:36])
        live_data, live_data_slot = account(url, live_programdata)
        live_raw = live_data["raw"]
        need(len(live_raw) >= 45 and struct.unpack_from("<I", live_raw)[0] == 3,
             "invalid live ProgramData account")
        live_deployed_at = struct.unpack_from("<Q", live_raw, 4)[0]
        live_raw = live_raw[45:]
    live_match_mode = elf_match_mode(elf, live_raw)
    live_hash_matches = live_match_mode is not None
    version_verified = (live_hash_matches and live_data_slot >= transaction["slot"] and
                        (live_deployed_at is None or live_deployed_at <= transaction["slot"]))
    if live_hash_matches:
        deployed_at_slot = live_deployed_at
    else:
        notes.append("Pinned ELF differs from the live program; its version at the transaction slot is unverified")
    if not version_verified and live_hash_matches:
        notes.append("Live deployment slot does not prove this ELF was active at the transaction slot")
    observed_slot = observed_slots[0]
    notes.append("Standard RPC returned account bytes at observation slot, not pre-transaction state")
    if inner_index is not None:
        notes.append("Inner CPI signer flags may include PDA signatures not recoverable from message header")
    if signer_overrides:
        notes.append("Signer flags manually overridden for: " + ", ".join(signer_overrides))
    if observed_slot != transaction["slot"]:
        notes.append("Account observation slot differs from transaction slot")
    fixture = {
        "schema_version": 1,
        "program": {
            "id": program_id, "elf": os.path.relpath(elf_path.resolve(), output.parent.resolve()),
            "sha256": hashlib.sha256(elf).hexdigest(),
            "loader": live_owner if live_hash_matches else program_meta.get("owner"),
            "deployed_at_slot": deployed_at_slot,
            "version_observed_slot": live_data_slot if live_hash_matches else None,
            "version_match_mode": live_match_mode,
        },
        "extra_programs": extra_programs,
        "transaction_base64": transaction_base64,
        "origin": {
            "kind": "transaction", "replay_mode": "full_transaction" if full_transaction else "instruction",
            "signature": signature,
            "instruction_index": instruction_index, "inner_index": inner_index,
            "transaction_slot": transaction["slot"],
            "account_observed_slot": observed_slot, "state_exact": False,
            "program_version_verified": version_verified,
            "signer_overrides": signer_overrides,
            "route_context_sysvar_base64": serialize_route_context_sysvar(
                transaction, instruction_index) if inner_index is not None and not full_transaction else None,
        },
        "payer": payer,
        "instruction": {
            "program_id": program_id, "accounts": metas,
            "data_base64": base64.b64encode(b58decode(selected["data"])).decode(),
        },
        "accounts": accounts, "mutations": [], "notes": notes,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n")
    return {"fixture": str(output), "program_id": program_id,
            "program_sha256": fixture["program"]["sha256"],
            "transaction_slot": transaction["slot"],
            "account_observed_slot": observed_slot,
            "instruction_accounts": len(metas), "full_transaction": full_transaction,
            "total_transaction_accounts": len(addresses), "extra_programs": len(extra_programs),
            "state_exact": False,
            "program_version_verified": version_verified,
            "notes": notes}


def hydrate_fixture(path: Path, output: Path, rpc_env: str, slot: int | None,
                    provider: str, capture_features: bool = False) -> dict:
    """Replace a fixture's live account snapshot with archived pre-slot bytes."""
    fixture = json.loads(path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported replay fixture schema")
    origin = fixture["origin"]
    transaction_slot = origin.get("transaction_slot")
    need(transaction_slot is not None and transaction_slot > 0,
         "fixture needs a positive transaction slot")
    if slot is None:
        slot = transaction_slot - 1
    need(0 <= slot < transaction_slot,
         "archive slot must precede the transaction slot")
    url = os.environ.get(rpc_env, "")
    need(url.startswith("https://"),
         f"environment variable {rpc_env} must contain an HTTPS archive RPC URL")
    need(bool(provider.strip()), "provider label cannot be empty")

    def archived_account(pubkey: str) -> tuple[dict | None, bytes | None]:
        result = rpc(url, "getAccountInfo", [pubkey, {
            "slot": slot, "encoding": "base64", "commitment": "finalized",
        }])
        need(result["context"]["slot"] == slot,
             f"archive returned unexpected slot for {pubkey}")
        value = result["value"]
        if value is None:
            return None, None
        need(value["data"][1] == "base64", "archive did not return base64")
        raw = base64.b64decode(value["data"][0], validate=True)
        need(value.get("space", len(raw)) == len(raw),
             f"archive account {pubkey} space/data length mismatch")
        return value, raw

    accounts = {}
    missing = []
    for pubkey in fixture["accounts"]:
        value, raw = archived_account(pubkey)
        if value is None or value["executable"]:
            accounts[pubkey] = None
            missing.append(pubkey)
            continue
        accounts[pubkey] = {
            "lamports": value["lamports"], "owner": value["owner"],
            "executable": False, "rent_epoch": value["rentEpoch"],
            "data_base64": base64.b64encode(raw).decode(),
        }

    program = fixture["program"]
    program_info, program_raw = archived_account(program["id"])
    need(program_info is not None and program_info["executable"],
         "target program was not executable at the archive slot")
    archived_deployment = None
    if program_info["owner"] == "BPFLoaderUpgradeab1e11111111111111111111111":
        need(len(program_raw) >= 36 and struct.unpack_from("<I", program_raw)[0] == 2,
             "invalid archived upgradeable Program account")
        programdata_id = b58encode(program_raw[4:36])
        programdata_info, programdata_raw = archived_account(programdata_id)
        need(programdata_info is not None and len(programdata_raw) >= 45 and
             struct.unpack_from("<I", programdata_raw)[0] == 3,
             "invalid archived ProgramData account")
        archived_deployment = struct.unpack_from("<Q", programdata_raw, 4)[0]
        archived_elf = programdata_raw[45:]
    else:
        archived_elf = program_raw
    archived_hash = hashlib.sha256(archived_elf).hexdigest()
    target_elf = (path.parent / program["elf"]).resolve().read_bytes()
    need(hashlib.sha256(target_elf).hexdigest() == program["sha256"],
         "fixture's pinned ELF hash does not match its file")
    match_mode = elf_match_mode(target_elf, archived_elf)
    version_verified = match_mode is not None
    program["archive_match_mode"] = match_mode
    program["archived_sha256"] = archived_hash
    program["archived_deployed_at_slot"] = archived_deployment
    if version_verified:
        program["loader"] = program_info["owner"]
        program["version_observed_slot"] = slot
        program["deployed_at_slot"] = archived_deployment

    balance_validation = {"lamport_checks": 0, "token_amount_checks": 0,
                          "mismatches": []}
    signature = origin.get("signature")
    if signature:
        transaction = rpc(url, "getTransaction", [signature, {
            "encoding": "json", "commitment": "finalized",
            "maxSupportedTransactionVersion": 1,
        }])
        need(transaction is not None and transaction["slot"] == transaction_slot,
             "archive transaction missing or slot differs from fixture")
        if (origin.get("inner_index") is not None and
                origin.get("replay_mode") != "full_transaction"):
            origin["route_context_sysvar_base64"] = serialize_route_context_sysvar(
                transaction, origin["instruction_index"])
        message = transaction["transaction"]["message"]
        loaded = (transaction.get("meta") or {}).get("loadedAddresses") or {}
        keys = message["accountKeys"] + loaded.get("writable", []) + loaded.get("readonly", [])
        for index, amount in enumerate(transaction["meta"].get("preBalances") or []):
            if index >= len(keys):
                break
            record = accounts.get(keys[index])
            if record is None:
                continue
            balance_validation["lamport_checks"] += 1
            if record["lamports"] != amount:
                balance_validation["mismatches"].append({
                    "account": keys[index], "field": "lamports",
                    "archive": record["lamports"], "transaction_pre": amount})
        for row in transaction["meta"].get("preTokenBalances") or []:
            index = row["accountIndex"]
            if index >= len(keys):
                continue
            record = accounts.get(keys[index])
            if record is None:
                continue
            data = base64.b64decode(record["data_base64"], validate=True)
            if len(data) < 72:
                continue
            amount = int(row["uiTokenAmount"]["amount"])
            actual = struct.unpack_from("<Q", data, 64)[0]
            balance_validation["token_amount_checks"] += 1
            if actual != amount:
                balance_validation["mismatches"].append({
                    "account": keys[index], "field": "spl_token_amount",
                    "archive": actual, "transaction_pre": amount})

    clock_result = rpc(url, "getAccountInfo", [
        "SysvarC1ock11111111111111111111111111111111", {
            "slot": transaction_slot, "encoding": "base64", "commitment": "finalized",
        }])
    need(clock_result["context"]["slot"] == transaction_slot and
         clock_result["value"] is not None,
         "archive did not return the transaction-slot Clock sysvar")
    clock_data = base64.b64decode(clock_result["value"]["data"][0], validate=True)
    need(len(clock_data) == 40 and
         struct.unpack_from("<Q", clock_data)[0] == transaction_slot,
         "archived Clock sysvar has an unexpected layout or slot")
    origin["clock_sysvar_base64"] = base64.b64encode(clock_data).decode()
    sysvar_ids = {
        "rent": "SysvarRent111111111111111111111111111111111",
        "epoch_schedule": "SysvarEpochSchedu1e111111111111111111111111",
        "last_restart_slot": "SysvarLastRestartS1ot1111111111111111111111",
        "epoch_rewards": "SysvarEpochRewards1111111111111111111111111",
        "slot_hashes": "SysvarS1otHashes111111111111111111111111111",
        "stake_history": "SysvarStakeHistory1111111111111111111111111",
    }
    historical_sysvars = {}
    for name, pubkey in sysvar_ids.items():
        result = rpc(url, "getAccountInfo", [pubkey, {
            "slot": transaction_slot, "encoding": "base64", "commitment": "finalized",
        }])
        need(result["context"]["slot"] == transaction_slot,
             f"archive returned unexpected slot for {name} sysvar")
        value = result["value"]
        if value is not None:
            need(value["data"][1] == "base64", f"archive {name} is not base64")
            historical_sysvars[name] = value["data"][0]
    origin["sysvars_base64"] = historical_sysvars
    if capture_features:
        runner = Path(__file__).resolve().parent / "replay/target/debug/soldecomp-replay"
        need(runner.exists(), "build the replay runner before --features")
        feature_ids = json.loads(subprocess.run(
            [str(runner), "--feature-ids"], capture_output=True, text=True,
            check=True).stdout)
        need(isinstance(feature_ids, list) and feature_ids,
             "replay runner returned no feature IDs")
        activation_slots = {}
        missing_features = []
        observation_slots = []
        for start in range(0, len(feature_ids), 100):
            group = feature_ids[start:start + 100]
            result = rpc(url, "getMultipleAccounts", [group, {
                "encoding": "base64", "commitment": "finalized",
            }])
            need(result["context"]["slot"] >= transaction_slot and
                 len(result["value"]) == len(group),
                 "feature RPC returned an older slot or wrong account count")
            observation_slots.append(result["context"]["slot"])
            for pubkey, value in zip(group, result["value"], strict=True):
                if value is None:
                    missing_features.append(pubkey)
                    continue
                data = base64.b64decode(value["data"][0], validate=True)
                if (value["owner"] != "Feature111111111111111111111111111111111111"
                        or len(data) != 9 or data[0] not in (0, 1)):
                    missing_features.append(pubkey)
                    continue
                if data[0] == 1:
                    activated_at = struct.unpack_from("<Q", data, 1)[0]
                    if activated_at <= transaction_slot:
                        activation_slots[pubkey] = activated_at
        origin["feature_activation_slots"] = activation_slots
        origin["feature_snapshot"] = {"slot": transaction_slot,
                                      "catalog_size": len(feature_ids),
                                      "active_count": len(activation_slots),
                                      "observed_slots": observation_slots,
                                      "missing_feature_accounts": missing_features,
                                      "method": "current_activation_slots_filtered_by_target_slot",
                                      "provider": provider}
        fixture.setdefault("notes", []).append(
            "Feature activation slots were read from current feature accounts and filtered by target slot; removed feature accounts and runtime-version differences remain possible.")

    for extra in fixture.get("extra_programs", []):
        extra_info, extra_raw = archived_account(extra["id"])
        need(extra_info is not None and extra_info["executable"],
             f"invoked program {extra['id']} was not executable at archive slot")
        extra_owner = extra_info["owner"]
        extra_deployment = None
        if extra_owner == "BPFLoaderUpgradeab1e11111111111111111111111":
            need(len(extra_raw) >= 36 and struct.unpack_from("<I", extra_raw)[0] == 2,
                 f"invalid archived Program account {extra['id']}")
            data_id = b58encode(extra_raw[4:36])
            data_info, data_raw = archived_account(data_id)
            need(data_info is not None and len(data_raw) >= 45 and
                 struct.unpack_from("<I", data_raw)[0] == 3,
                 f"invalid archived ProgramData {data_id}")
            extra_deployment = struct.unpack_from("<Q", data_raw, 4)[0]
            extra_raw = data_raw[45:]
        else:
            need(extra_owner in {"BPFLoader2111111111111111111111111111111111",
                                 "BPFLoader1111111111111111111111111111111111"},
                 f"unsupported archived executable owner {extra_owner}")
        extra_elf = executable_elf_prefix(extra_raw)
        extra_hash = hashlib.sha256(extra_elf).hexdigest()
        extra_path = output.parent / "programs" / f"{extra['id']}-{extra_hash[:16]}.so"
        extra_path.parent.mkdir(parents=True, exist_ok=True)
        extra_path.write_bytes(extra_elf)
        extra.update({"elf": os.path.relpath(extra_path.resolve(), path.parent.resolve()),
                      "sha256": extra_hash, "loader": extra_owner,
                      "deployed_at_slot": extra_deployment,
                      "version_observed_slot": slot,
                      "archive_match_mode": elf_match_mode(extra_elf, extra_raw)})
    for item in [program] + fixture.get("extra_programs", []):
        item["elf"] = os.path.relpath((path.parent / item["elf"]).resolve(),
                                      output.parent.resolve())
    fixture["accounts"] = accounts
    origin["account_observed_slot"] = slot
    origin["account_state_source"] = {"kind": "slot_archive", "provider": provider,
                                      "slot": slot, "relation": "before_transaction_slot"}
    origin["state_exact"] = False
    origin["program_version_verified"] = version_verified
    stale = ("Standard RPC returned account bytes", "Account observation slot differs",
             "Pinned ELF differs from the live program", "Live deployment slot does not prove")
    fixture["notes"] = [note for note in fixture.get("notes", [])
                        if not note.startswith(stale)]
    fixture["notes"].append(
        "Archived account bytes are exact as of the preceding slot, not necessarily immediately before this instruction within its slot or transaction.")
    if balance_validation["mismatches"]:
        fixture["notes"].append(
            "Archived pre-slot balances differ from transaction pre-balances; another write may have occurred in the same slot.")
    if not version_verified:
        fixture["notes"].append(
            "Archived program bytes differ from the fixture's pinned ELF at this slot.")
    elif match_mode == "zero_padded_prefix":
        fixture["notes"].append(
            "Archived ProgramData contains the pinned ELF followed only by zero-filled allocated space; full account-data hash differs.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n")
    return {"fixture": str(output), "slot": slot,
            "program_version_verified": version_verified,
            "program_match_mode": match_mode,
            "archived_program_sha256": archived_hash,
            "accounts_hydrated": len(accounts) - len(missing),
            "accounts_missing_or_executable": missing,
            "balance_validation": balance_validation,
            "historical_sysvars": sorted(historical_sysvars),
            "active_features": len(origin.get("feature_activation_slots", {}))
                if capture_features else None,
            "state_exact": False}


def mutate_fixture(path: Path, output: Path, name: str, account_id: str | None,
                   token_amount_delta: int | None, offset: int | None,
                   bytes_hex: str | None, lamports: int | None,
                   instruction_hex: str | None) -> dict:
    """Append one controlled input change to a replay fixture."""
    fixture = json.loads(path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported replay fixture schema")
    need(name and name != "baseline", "mutation name cannot be empty or baseline")
    need(all(item["name"] != name for item in fixture.get("mutations", [])),
         f"mutation {name} already exists")
    change = {"name": name, "account": account_id or ""}
    if instruction_hex is not None:
        need(not account_id, "--account is not used with --instruction-hex")
        change["instruction_data_base64"] = base64.b64encode(bytes.fromhex(instruction_hex)).decode()
    else:
        need(account_id is not None, "--account is required for account mutation")
        record = fixture["accounts"].get(account_id)
        need(record is not None, f"account {account_id} is absent from fixture")
        data = base64.b64decode(record["data_base64"], validate=True)
        if token_amount_delta is not None:
            need(record["owner"] in {
                KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"],
                KNOWN_PROGRAM_IDS["SOLANA_TOKEN_2022_PROGRAM_ID"],
            } and len(data) >= 165, "account is not a standard SPL token account")
            before = struct.unpack_from("<Q", data, 64)[0]
            after = before + token_amount_delta
            need(0 <= after <= 2**64 - 1, "token amount change overflows u64")
            change.update({"offset": 64, "data_base64": base64.b64encode(
                struct.pack("<Q", after)).decode()})
        elif bytes_hex is not None:
            need(offset is not None and offset >= 0, "--offset must be non-negative")
            raw = bytes.fromhex(bytes_hex)
            need(raw and offset + len(raw) <= len(data),
                 "byte patch must fit within existing account data")
            change.update({"offset": offset, "data_base64": base64.b64encode(raw).decode()})
        else:
            need(lamports is not None and 0 <= lamports <= 2**64 - 1,
                 "lamports must fit u64")
            change["lamports"] = lamports
    for program in [fixture["program"]] + fixture.get("extra_programs", []):
        program["elf"] = os.path.relpath((path.parent / program["elf"]).resolve(),
                                         output.parent.resolve())
    fixture.setdefault("mutations", []).append(change)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n")
    return {"fixture": str(output), "mutation": name, "account": account_id,
            "token_amount_delta": token_amount_delta,
            "offset": change.get("offset")}



def apply_replay_account_state(fixture_path: Path, replay_path: Path,
                               account_id: str, output: Path, name: str) -> dict:
    """Carry one checked account result from an earlier replay into a fixture."""
    need(output.resolve() != fixture_path.resolve(),
         "write the updated fixture to a new path")
    fixture = json.loads(fixture_path.read_text())
    replay = json.loads(replay_path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported target fixture schema")
    source_origin = replay["origin"]
    target_origin = fixture["origin"]
    need(source_origin.get("program_version_verified"),
         "source replay did not verify its historical program version")
    source_slot = source_origin.get("transaction_slot")
    target_slot = target_origin.get("transaction_slot")
    need(isinstance(source_slot, int) and isinstance(target_slot, int) and
         source_slot <= target_slot,
         "source transaction must be no later than target transaction slot")
    matches = [row for row in replay["scenarios"] if row["name"] == name]
    need(len(matches) == 1 and matches[0]["success"],
         "selected source replay scenario is missing or failed")
    change = matches[0]["changes"].get(account_id)
    need(change is not None and change.get("before") and change.get("after"),
         "source replay did not change this existing account")
    before, after = change["before"], change["after"]
    need(after.get("data_base64") is not None,
         "source replay needs --include-account-data")
    target = fixture["accounts"].get(account_id)
    need(target is not None, "target fixture does not contain this account")
    prior_data = base64.b64decode(target["data_base64"], validate=True)
    need(hashlib.sha256(prior_data).hexdigest() == before["data_sha256"] and
         target["lamports"] == before["lamports"] and
         target["owner"] == before["owner"] and
         target["executable"] == before["executable"] and
         target["rent_epoch"] == before["rent_epoch"],
         "target account does not match the source replay's initial state")
    after_data = base64.b64decode(after["data_base64"], validate=True)
    need(hashlib.sha256(after_data).hexdigest() == after["data_sha256"] and
         len(after_data) == after["data_len"],
         "source replay's exported account data failed its hash check")
    fixture["accounts"][account_id] = {
        "lamports": after["lamports"], "owner": after["owner"],
        "executable": after["executable"], "rent_epoch": after["rent_epoch"],
        "data_base64": after["data_base64"],
    }
    target_origin.setdefault("replayed_account_updates", []).append({
        "account": account_id, "source_signature": source_origin.get("signature"),
        "source_transaction_slot": source_slot, "source_scenario": name,
        "source_program_id": replay["program"]["id"],
        "source_program_sha256": replay["program"]["sha256"],
        "before_sha256": before["data_sha256"],
        "after_sha256": after["data_sha256"],
    })
    fixture.setdefault("notes", []).append(
        f"Account {account_id} was reconstructed from a successful earlier local replay; verify on-chain transaction order and runtime agreement before treating it as exact state.")
    for program in [fixture["program"]] + fixture.get("extra_programs", []):
        program["elf"] = os.path.relpath((fixture_path.parent / program["elf"]).resolve(),
                                         output.parent.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n")
    return {"fixture": str(output), "account": account_id,
            "source_signature": source_origin.get("signature"),
            "source_slot": source_slot, "target_slot": target_slot,
            "before_sha256": before["data_sha256"],
            "after_sha256": after["data_sha256"]}


def archive_simulate_fixture(path: Path, output: Path, rpc_env: str,
                             names: list[str]) -> dict:
    """Run the original full transaction on archived state, with account changes."""
    fixture = json.loads(path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported replay fixture schema")
    origin = fixture["origin"]
    source = origin.get("account_state_source") or {}
    need(source.get("kind") == "slot_archive", "hydrate the fixture from a slot archive first")
    need(origin.get("program_version_verified") and
         (fixture["program"].get("archive_match_mode") in
          ("exact_bytes", "zero_padded_prefix") or
          fixture["program"].get("archived_sha256") == fixture["program"]["sha256"]),
         "pinned ELF was not verified at the archived slot")
    slot = source["slot"]
    transaction_slot = origin["transaction_slot"]
    need(slot < transaction_slot and origin.get("signature"),
         "fixture needs an archived pre-transaction slot and signature")
    url = os.environ.get(rpc_env, "")
    need(url.startswith("https://"),
         f"environment variable {rpc_env} must contain an HTTPS archive RPC URL")
    need(len(names) <= 4 and len(names) == len(set(names)),
         "select at most four distinct mutations")
    mutations = {item["name"]: item for item in fixture.get("mutations", [])}
    for name in names:
        need(name in mutations, f"unknown mutation: {name}")
        need("instruction_data_base64" not in mutations[name],
             "full transaction archive replay supports account mutations only")

    signature = origin["signature"]
    transaction = rpc(url, "getTransaction", [signature, {
        "encoding": "base64", "commitment": "finalized",
        "maxSupportedTransactionVersion": 1,
    }])
    need(transaction is not None and transaction["slot"] == transaction_slot,
         "transaction missing or slot differs from fixture")
    encoded = transaction["transaction"][0]
    transaction_json = rpc(url, "getTransaction", [signature, {
        "encoding": "json", "commitment": "finalized",
        "maxSupportedTransactionVersion": 1,
    }])
    message = transaction_json["transaction"]["message"]
    loaded = (transaction_json["meta"].get("loadedAddresses") or {})
    keys = message["accountKeys"] + loaded.get("writable", []) + loaded.get("readonly", [])
    pre = {row["accountIndex"]: int(row["uiTokenAmount"]["amount"])
           for row in transaction_json["meta"].get("preTokenBalances") or []}
    post = {row["accountIndex"]: int(row["uiTokenAmount"]["amount"])
            for row in transaction_json["meta"].get("postTokenBalances") or []}
    actual_deltas = {keys[index]: post[index] - amount
                     for index, amount in pre.items() if index in post and index < len(keys)}
    token_programs = {KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"],
                      KNOWN_PROGRAM_IDS["SOLANA_TOKEN_2022_PROGRAM_ID"]}
    observed = {pubkey: record for pubkey, record in fixture["accounts"].items()
                if record is not None and record["owner"] in token_programs and
                len(base64.b64decode(record["data_base64"], validate=True)) >= 72}
    need(observed, "fixture has no token accounts to observe")
    clock_id = "SysvarC1ock11111111111111111111111111111111"
    results = []
    for name in ["baseline"] + names:
        override = {clock_id: {"slot": transaction_slot}}
        modified_data = {}
        if name != "baseline":
            mutation = mutations[name]
            account_id = mutation["account"]
            record = fixture["accounts"].get(account_id)
            need(record is not None, f"mutation account absent: {account_id}")
            if "data_base64" in mutation:
                data = bytearray(base64.b64decode(record["data_base64"], validate=True))
                patch = base64.b64decode(mutation["data_base64"], validate=True)
                offset = mutation["offset"]
                need(0 <= offset <= len(data) - len(patch),
                     f"mutation {name} exceeds account data")
                data[offset:offset + len(patch)] = patch
                override[account_id] = {"data": [base64.b64encode(data).decode(), "base64"]}
                modified_data[account_id] = data
            elif "lamports" in mutation:
                override[account_id] = {"lamports": mutation["lamports"]}
            else:
                raise ValueError(f"mutation {name} has no account change")
        request = {"simulations": [{"slot": slot, "encodedTransaction": encoded,
                                     "stateOverrides": override}],
                   "postExecutionAccountsConfigs": {
                       "accounts": list(observed), "encoding": "base64"},
                   "innerInstructions": False, "sigVerify": False,
                   "replaceRecentBlockhash": True}
        response = rpc(url, "simulateTransactionsAtSlot", [request])
        rows = response["value"]["simulationResults"]
        need(len(rows) == 1, "archive simulator returned an unexpected result count")
        row = rows[0]
        post_accounts = {entry["address"]: entry["account"]
                         for entry in row.get("postExecutionAccounts") or []
                         if entry.get("account")}
        effects = {}
        for pubkey, record in observed.items():
            before_data = modified_data.get(pubkey)
            if before_data is None:
                before_data = base64.b64decode(record["data_base64"], validate=True)
            before_amount = struct.unpack_from("<Q", before_data, 64)[0]
            after_amount = before_amount
            if pubkey in post_accounts:
                value = post_accounts[pubkey]
                need(value["data"][1] == "base64", "archive returned non-base64 account data")
                data = base64.b64decode(value["data"][0], validate=True)
                need(len(data) >= 72, f"archive returned short token account {pubkey}")
                after_amount = struct.unpack_from("<Q", data, 64)[0]
            effects[pubkey] = {"before": before_amount,
                               "after": after_amount if row["status"] == "success" else None,
                               "delta": (after_amount - before_amount)
                                        if row["status"] == "success" else None}
        results.append({"name": name, "status": row["status"], "error": row["err"],
                        "compute_units": row.get("unitsConsumed"),
                        "logs": row.get("logs") or [], "token_effects": effects})

    baseline = results[0]
    differences = {pubkey: {"actual": delta,
                            "simulated": baseline["token_effects"][pubkey]["delta"]}
                   for pubkey, delta in actual_deltas.items()
                   if pubkey in observed and
                   baseline["token_effects"][pubkey]["delta"] != delta}
    report = {"schema_version": 1, "kind": "archive_full_transaction_simulation",
              "provider": source.get("provider"), "signature": signature,
              "archive_state_slot": slot, "execution_clock_slot": transaction_slot,
              "program_id": fixture["program"]["id"],
              "program_sha256": fixture["program"]["sha256"],
              "actual_transaction_error": transaction_json["meta"]["err"],
              "actual_token_deltas": {pubkey: delta for pubkey, delta in actual_deltas.items()
                                      if pubkey in observed},
              "baseline_token_delta_differences": differences,
              "baseline_logs_match_actual": (
                  baseline["logs"] == transaction_json["meta"].get("logMessages")),
              "scenarios": results,
              "limitations": [
                  "The simulator runs the original full transaction against state as of the preceding slot, with Clock moved to the transaction slot.",
                  "Another transaction in the same slot may have written an account first; check block order before claiming exact pre-transaction state.",
                  "Account data overrides are counterfactual. A changed transaction outcome alone does not establish a profitable or reachable exploit.",
              ]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "baseline_status": baseline["status"],
            "baseline_token_delta_differences": differences,
            "baseline_logs_match_actual": report["baseline_logs_match_actual"],
            "scenarios": [{"name": row["name"], "status": row["status"],
                           "error": row["error"]} for row in results]}




def target_token_transfer_deltas(transaction: dict, origin: dict,
                                 keys: list[str], program_id: str) -> dict | None:
    """Extract SPL transfers made directly or indirectly by the selected call."""
    outer = origin.get("instruction_index")
    inner = origin.get("inner_index")
    instructions = transaction["transaction"]["message"]["instructions"]
    need(isinstance(outer, int) and 0 <= outer < len(instructions),
         "fixture outer instruction index is invalid")
    groups = [group["instructions"] for group in
              transaction["meta"].get("innerInstructions") or []
              if group["index"] == outer]
    if len(groups) != 1:
        return None
    group = groups[0]
    if inner is None:
        selected = instructions[outer]
        descendants = group
    else:
        need(isinstance(inner, int) and 0 <= inner < len(group),
             "fixture inner instruction index is invalid")
        selected = group[inner]
        depth = selected.get("stackHeight")
        if depth is None:
            return None
        descendants = []
        for item in group[inner + 1:]:
            child_depth = item.get("stackHeight")
            if child_depth is None:
                return None
            if child_depth <= depth:
                break
            descendants.append(item)
    need(selected["programIdIndex"] < len(keys) and
         keys[selected["programIdIndex"]] == program_id,
         "fixture selected instruction is not the pinned program")
    token_programs = {KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"],
                      KNOWN_PROGRAM_IDS["SOLANA_TOKEN_2022_PROGRAM_ID"]}
    deltas: dict[str, int] = {}
    transfers = []
    for item in descendants:
        need(item["programIdIndex"] < len(keys),
             "inner instruction program index is out of range")
        if keys[item["programIdIndex"]] not in token_programs:
            continue
        data = b58decode(item["data"]) if item["data"] else b""
        if len(data) < 9 or data[0] not in (3, 12):
            continue
        accounts = item["accounts"]
        destination_index = 1 if data[0] == 3 else 2
        if len(accounts) <= destination_index:
            continue
        source_index, dest_index = accounts[0], accounts[destination_index]
        need(source_index < len(keys) and dest_index < len(keys),
             "inner token transfer account index is out of range")
        source, destination = keys[source_index], keys[dest_index]
        amount = int.from_bytes(data[1:9], "little")
        deltas[source] = deltas.get(source, 0) - amount
        deltas[destination] = deltas.get(destination, 0) + amount
        transfers.append({"source": source, "destination": destination,
                          "amount": amount, "opcode": data[0]})
    return {"selected_call_depth": selected.get("stackHeight", 1),
            "descendant_instruction_count": len(descendants),
            "recognized_token_transfers": transfers,
            "token_deltas": deltas}



def prior_dependency_closure(transactions: list[dict], target_index: int,
                             seeds: set[str], max_writers: int = 64) -> dict:
    """Walk successful account writers backwards through their read dependencies."""
    need(max_writers > 0, "max_writers must be positive")
    needed = set(seeds)
    selected = []
    for index in range(target_index - 1, -1, -1):
        row = transactions[index]
        keys = row["transaction"]["accountKeys"]
        meta = row.get("meta", {})
        if meta.get("err") is not None:
            payer = keys[0]["pubkey"] if keys else None
            fee = meta.get("fee")
            if payer in needed and fee != 0:
                selected.append({"signature": row["transaction"]["signatures"][0],
                                 "transaction_index": index, "kind": "failed_fee",
                                 "needed_writes": [payer], "new_dependencies": [],
                                 "fee_lamports": fee})
                need(len(selected) <= max_writers,
                     f"dependency closure exceeds {max_writers} earlier transactions")
            continue
        written = {item["pubkey"] for item in keys if item.get("writable")}
        overlap = written & needed
        if not overlap:
            continue
        signature = row["transaction"]["signatures"][0]
        selected.append({"signature": signature, "transaction_index": index,
                         "kind": "successful_replay",
                         "needed_writes": sorted(overlap),
                         "new_dependencies": sorted({item["pubkey"] for item in keys} - needed)})
        needed.update(item["pubkey"] for item in keys)
        need(len(selected) <= max_writers,
             f"dependency closure exceeds {max_writers} earlier transactions; narrow the fixture or raise the limit")
    selected.reverse()
    return {"writers": selected, "seed_accounts": sorted(seeds),
            "dependency_accounts": sorted(needed),
            "writer_count": len(selected)}


def audit_block_order(fixture: dict, block: dict) -> dict:
    """Find earlier same-slot writes to archived fixture accounts."""
    origin = fixture["origin"]
    signature = origin.get("signature")
    need(signature and origin.get("transaction_slot") is not None,
         "fixture needs a transaction signature and slot")
    transactions = block.get("transactions") if block else None
    need(isinstance(transactions, list), "block has no transaction account records")
    positions = [index for index, row in enumerate(transactions)
                 if signature in row["transaction"]["signatures"]]
    need(len(positions) == 1, "target signature appears zero or multiple times in block")
    position = positions[0]
    tracked = {pubkey for pubkey, account in fixture["accounts"].items()
               if account is not None}
    writes: dict[str, list[dict]] = {}
    for index, row in enumerate(transactions):
        if index == position or row["meta"].get("err") is not None:
            continue
        for account in row["transaction"]["accountKeys"]:
            pubkey = account["pubkey"]
            if account.get("writable") and pubkey in tracked:
                writes.setdefault(pubkey, []).append({
                    "transaction_index": index,
                    "signature": row["transaction"]["signatures"][0],
                    "relative_to_target": "before" if index < position else "after",
                })
    prior = {pubkey: [item for item in rows if item["relative_to_target"] == "before"]
             for pubkey, rows in writes.items()}
    prior = {pubkey: rows for pubkey, rows in prior.items() if rows}
    later = {pubkey: [item for item in rows if item["relative_to_target"] == "after"]
             for pubkey, rows in writes.items()}
    later = {pubkey: rows for pubkey, rows in later.items() if rows}
    closure = prior_dependency_closure(transactions, position, tracked)
    return {
        "schema_version": 1, "kind": "same_slot_account_write_audit",
        "signature": signature, "transaction_slot": origin["transaction_slot"],
        "transaction_index_in_block": position,
        "block_transaction_count": len(transactions),
        "tracked_account_count": len(tracked),
        "prior_successful_writes": prior, "later_successful_writes": later,
        "prior_dependency_closure": closure,
        "pre_slot_snapshot_unmodified_before_transaction": not prior,
        "limitations": [
            "Writable account flags identify possible account changes; they do not prove the account data changed.",
            "Failed program writes roll back; failed transaction fees are included when the fee payer is needed.",
            "This checks state before the transaction, not state after parent instructions and before a selected inner CPI.",
            "The dependency closure is conservative: a writable flag can include a transaction that did not change relevant data.",
        ],
    }


def audit_slot_fixture(path: Path, output: Path, rpc_env: str) -> dict:
    fixture = json.loads(path.read_text())
    origin = fixture["origin"]
    need(origin.get("transaction_slot") is not None,
         "fixture needs a transaction slot")
    url = os.environ.get(rpc_env, "")
    need(url.startswith("https://"),
         f"environment variable {rpc_env} must contain an HTTPS archive RPC URL")
    block = rpc(url, "getBlock", [origin["transaction_slot"], {
        "encoding": "json", "transactionDetails": "accounts", "rewards": False,
        "maxSupportedTransactionVersion": 1,
    }])
    result = audit_block_order(fixture, block)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    return {"report": str(output),
            "transaction_index_in_block": result["transaction_index_in_block"],
            "prior_successful_writes": result["prior_successful_writes"],
            "pre_slot_snapshot_unmodified_before_transaction":
                result["pre_slot_snapshot_unmodified_before_transaction"]}


def reconstruct_same_slot(path: Path, output: Path, rpc_env: str,
                          runner: Path) -> dict:
    """Replay earlier writable transactions and carry their account state forward."""
    fixture = json.loads(path.read_text())
    origin = fixture["origin"]
    slot = origin.get("transaction_slot")
    need(isinstance(slot, int) and slot > 0 and origin.get("signature"),
         "fixture needs a historical transaction signature and slot")
    source = origin.get("account_state_source") or {}
    need(source.get("slot") == slot - 1,
         "reconstruct-slot requires a fixture hydrated from the preceding slot")
    need(origin.get("program_version_verified"),
         "target ELF is not verified against archived ProgramData")
    url = os.environ.get(rpc_env, "")
    need(url.startswith("https://"),
         f"environment variable {rpc_env} must contain an HTTPS archive RPC URL")
    source_path = path
    if origin.get("replayed_account_updates"):
        # A pinned case may already contain direct-writer updates. Rebuild its
        # pre-slot baseline before applying the complete dependency closure.
        fresh = output.with_suffix(".pre-slot.json")
        hydrate_fixture(path, fresh, rpc_env, slot - 1,
                        source.get("provider", "archive-rpc"))
        path = fresh
        fixture = json.loads(path.read_text())
        origin = fixture["origin"]
        origin.pop("replayed_account_updates", None)
    block = rpc(url, "getBlock", [slot, {
        "encoding": "json", "transactionDetails": "accounts", "rewards": False,
        "maxSupportedTransactionVersion": 1,
    }])
    audit = audit_block_order(fixture, block)
    tracked = set(fixture["accounts"])
    closure = audit["prior_dependency_closure"]
    ordered = closure["writers"]
    work = output.parent / (output.stem + "-writers")
    work.mkdir(parents=True, exist_ok=True)
    overlay: dict[str, dict] = {}
    writers = []

    def matches(record: dict | None, state: dict | None) -> bool:
        if state is None:
            return record is None
        if record is None:
            return False
        raw = base64.b64decode(record["data_base64"], validate=True)
        return (record["lamports"] == state["lamports"] and
                record["owner"] == state["owner"] and
                record["executable"] == state["executable"] and
                record["rent_epoch"] == state["rent_epoch"] and
                hashlib.sha256(raw).hexdigest() == state["data_sha256"])

    def record_from(state: dict | None) -> dict | None:
        if state is None:
            return None
        data = state.get("data_base64")
        need(data is not None and
             hashlib.sha256(base64.b64decode(data, validate=True)).hexdigest() ==
             state["data_sha256"], "replay account data failed its hash check")
        return {key: state[key] for key in ("lamports", "owner", "executable",
                                            "rent_epoch", "data_base64")}

    def state_from_record(record: dict) -> dict:
        raw = base64.b64decode(record["data_base64"], validate=True)
        return {"lamports": record["lamports"], "owner": record["owner"],
                "executable": record["executable"],
                "rent_epoch": record["rent_epoch"],
                "data_sha256": hashlib.sha256(raw).hexdigest()}

    for selected_writer in ordered:
        signature, index = (selected_writer["signature"],
                            selected_writer["transaction_index"])
        if selected_writer.get("kind") == "failed_fee":
            pubkey = selected_writer["needed_writes"][0]
            fee = selected_writer["fee_lamports"]
            if fee is None:
                failed_transaction = rpc(url, "getTransaction", [signature, {
                    "encoding": "json", "commitment": "finalized",
                    "maxSupportedTransactionVersion": 1,
                }])
                need(failed_transaction is not None and
                     failed_transaction["meta"].get("err") is not None,
                     f"failed transaction {signature} is unavailable")
                fee = failed_transaction["meta"]["fee"]
            need(isinstance(fee, int) and fee > 0,
                 f"failed transaction {signature} has no positive fee")
            previous = overlay.get(pubkey)
            if previous:
                current = previous["latest"]
                original = previous["original"]
            elif pubkey in fixture["accounts"]:
                current = fixture["accounts"][pubkey]
                need(current is not None, f"failed fee payer {pubkey} is absent")
                original = state_from_record(current)
            else:
                archived = rpc(url, "getAccountInfo", [pubkey, {
                    "slot": slot - 1, "encoding": "base64", "commitment": "finalized",
                }])
                need(archived["context"]["slot"] == slot - 1 and
                     archived["value"] is not None,
                     f"failed fee payer {pubkey} lacks an archived baseline")
                value = archived["value"]
                current = {"lamports": value["lamports"], "owner": value["owner"],
                           "executable": value["executable"],
                           "rent_epoch": value["rentEpoch"],
                           "data_base64": value["data"][0]}
                original = state_from_record(current)
            need(current["lamports"] >= fee,
                 f"failed transaction {signature} fee exceeds payer balance")
            updated = dict(current)
            updated["lamports"] -= fee
            overlay[pubkey] = {"original": original, "latest": updated,
                               "source_signature": signature,
                               "source_program": "transaction_fee"}
            writers.append({"signature": signature, "transaction_index": index,
                            "kind": "failed_fee", "fee_lamports": fee,
                            "changed_target_accounts": [pubkey] if pubkey in tracked else []})
            continue
        transaction = rpc(url, "getTransaction", [signature, {
            "encoding": "json", "commitment": "finalized",
            "maxSupportedTransactionVersion": 1,
        }])
        need(transaction is not None and transaction["slot"] == slot and
             transaction["meta"]["err"] is None,
             f"earlier transaction {signature} is unavailable or failed")
        message = transaction["transaction"]["message"]
        loaded = transaction["meta"].get("loadedAddresses") or {}
        keys = message["accountKeys"] + loaded.get("writable", []) + loaded.get("readonly", [])
        selected = None
        for outer_index, item in enumerate(message["instructions"]):
            program_id = keys[item["programIdIndex"]]
            value = rpc(url, "getAccountInfo", [program_id, {
                "slot": slot - 1, "encoding": "base64",
            }])["value"]
            if value and value["executable"] and value["owner"] in {
                "BPFLoaderUpgradeab1e11111111111111111111111",
                "BPFLoader2111111111111111111111111111111111",
                "BPFLoader1111111111111111111111111111111111",
            }:
                selected = (outer_index, program_id)
                break
        need(selected is not None,
             f"earlier transaction {signature} has no replayable outer program")
        outer_index, program_id = selected
        directory = work / f"{index}-{signature[:12]}"
        directory.mkdir(parents=True, exist_ok=True)
        elf_path = directory / "primary.so"
        archived_program_elf(url, program_id, slot - 1, elf_path)
        captured = directory / "captured.json"
        hydrated = directory / "hydrated.json"
        prepared = directory / "prepared.json"
        report_path = directory / "replay.json"
        capture_transaction(signature, elf_path, outer_index, None, [], url,
                            captured, full_transaction=True)
        hydration = hydrate_fixture(captured, hydrated, rpc_env, slot - 1,
                                    source.get("provider", "archive-rpc"))
        need(hydration["program_version_verified"],
             f"earlier program {program_id} did not match its archived ELF")
        writer_fixture = json.loads(hydrated.read_text())
        for pubkey, item in overlay.items():
            if pubkey in writer_fixture["accounts"]:
                need(matches(writer_fixture["accounts"][pubkey], item["original"]),
                     f"archive baseline mismatch for {pubkey} in {signature}")
                writer_fixture["accounts"][pubkey] = item["latest"]
        for program in [writer_fixture["program"]] + writer_fixture.get("extra_programs", []):
            program["elf"] = os.path.relpath((hydrated.parent / program["elf"]).resolve(),
                                             prepared.parent.resolve())
        prepared.write_text(json.dumps(writer_fixture, indent=2) + "\n")
        replay_fixture(prepared, report_path, runner, include_account_data=True)
        replay = json.loads(report_path.read_text())
        baseline = replay["scenarios"][0]
        need(baseline["success"],
             f"earlier transaction {signature} failed in local full replay: {baseline['error']}")
        changed = []
        for pubkey, change in baseline["changes"].items():
            previous = overlay.get(pubkey)
            before = change["before"]
            if previous:
                need(matches(previous["latest"], before),
                     f"replay chain diverged for {pubkey} at {signature}")
                original = previous["original"]
            else:
                original = before
                if pubkey in tracked:
                    need(matches(fixture["accounts"].get(pubkey), original),
                         f"target archive baseline differs for {pubkey}")
            overlay[pubkey] = {"original": original,
                               "latest": record_from(change["after"]),
                               "source_signature": signature,
                               "source_program": program_id}
            if pubkey in tracked:
                changed.append(pubkey)
        writers.append({"signature": signature, "transaction_index": index,
                        "kind": "successful_replay",
                        "program_id": program_id, "replay": str(report_path),
                        "recorded_compute_units": transaction["meta"].get("computeUnitsConsumed"),
                        "local_compute_units": baseline["compute_units"],
                        "changed_target_accounts": changed})

    if origin.get("inner_index") is not None and not origin.get("route_context_sysvar_base64"):
        target_transaction = rpc(url, "getTransaction", [origin["signature"], {
            "encoding": "json", "commitment": "finalized",
            "maxSupportedTransactionVersion": 1,
        }])
        need(target_transaction is not None and target_transaction["slot"] == slot,
             "target transaction is unavailable for route context")
        origin["route_context_sysvar_base64"] = serialize_route_context_sysvar(
            target_transaction, origin["instruction_index"])
    for pubkey, item in overlay.items():
        if pubkey not in tracked:
            continue
        need(matches(fixture["accounts"].get(pubkey), item["original"]),
             f"target baseline mismatch for carried account {pubkey}")
        fixture["accounts"][pubkey] = item["latest"]
        origin.setdefault("replayed_account_updates", []).append({
            "account": pubkey, "source_signature": item["source_signature"],
            "source_program_id": item["source_program"],
            "method": "ordered_full_transaction_replay",
        })
    for program in [fixture["program"]] + fixture.get("extra_programs", []):
        program["elf"] = os.path.relpath((path.parent / program["elf"]).resolve(),
                                         output.parent.resolve())
    fixture.setdefault("notes", []).append(
        f"Replayed {len(writers)} earlier same-slot transactions; inspect the reconstruction report before treating state as historical truth.")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(fixture, indent=2) + "\n")
    report = {"kind": "same_slot_reconstruction", "source_fixture": str(source_path),
              "output_fixture": str(output), "transaction_slot": slot,
              "target_transaction_index": audit["transaction_index_in_block"],
              "prior_writer_count": len(writers),
              "dependency_account_count": len(closure["dependency_accounts"]),
              "carried_accounts": sorted(tracked & overlay.keys()),
              "writers": writers,
              "limitations": ["The backwards dependency closure includes successful earlier writers of captured accounts and all accounts read by those writers.",
                              "Local replay must match the historical runtime and all relevant predecessor state; compare logs, compute use, and account effects before accepting the candidate state.",
                              "For an inner CPI, parent instructions within the target transaction are not included in the carried state."]}
    report_path = output.with_suffix(".reconstruction.json")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return {"fixture": str(output), "report": str(report_path),
            "prior_writer_count": len(writers),
            "carried_accounts": sorted(tracked & overlay.keys())}


def compare_full_runtime(fixture: dict, replay: dict, transaction: dict) -> dict:
    """Locate the first recorded versus local compute and log divergence."""
    recorded = transaction["meta"].get("logMessages") or []
    local = replay["scenarios"][0]
    need(fixture["origin"].get("replay_mode") == "full_transaction",
         "runtime comparison requires a full-transaction fixture")
    consumed = re.compile(r"^Program (\S+) consumed (\d+) of (\d+) compute units$")
    mismatches = []
    for index in range(max(len(recorded), len(local["logs"]))):
        left = recorded[index] if index < len(recorded) else None
        right = local["logs"][index] if index < len(local["logs"]) else None
        if left == right:
            continue
        row = {"index": index, "recorded": left, "local": right}
        left_match = consumed.fullmatch(left or "")
        right_match = consumed.fullmatch(right or "")
        if left_match and right_match and left_match.group(1) == right_match.group(1):
            row["program_id"] = left_match.group(1)
            row["recorded_consumed"] = int(left_match.group(2))
            row["local_consumed"] = int(right_match.group(2))
            row["recorded_remaining_budget"] = int(left_match.group(3))
            row["local_remaining_budget"] = int(right_match.group(3))
        mismatches.append(row)
    report = {"kind": "full_runtime_comparison",
              "signature": fixture["origin"]["signature"],
              "recorded_success": transaction["meta"].get("err") is None,
              "local_success": local["success"],
              "recorded_compute_units": transaction["meta"].get("computeUnitsConsumed"),
              "local_compute_units": local["compute_units"],
              "compute_unit_difference": local["compute_units"] -
                  transaction["meta"].get("computeUnitsConsumed", 0),
              "recorded_log_count": len(recorded), "local_log_count": len(local["logs"]),
              "first_log_difference": mismatches[0] if mismatches else None,
              "log_differences": mismatches,
              "limitations": ["Matching logs and account effects do not prove identical validator execution.",
                              "The first remaining-budget difference bounds where extra compute was spent; it does not identify the exact instruction."]}
    return report



def runtime_gap_audit(fixture_path: Path, comparison_path: Path, output: Path) -> dict:
    """Attribute a recorded compute gap and record reproducible runtime inputs."""
    fixture = json.loads(fixture_path.read_text())
    comparison = json.loads(comparison_path.read_text())
    need(comparison.get("kind") == "full_runtime_comparison", "expected full runtime comparison")
    need(comparison.get("signature") == fixture["origin"].get("signature"),
         "runtime comparison signature differs from fixture")
    origin = fixture["origin"]
    packages = tomllib.loads((Path(__file__).resolve().parent /
                              "replay/Cargo.lock").read_text())["package"]
    wanted = {"litesvm", "solana-program-runtime", "agave-feature-set",
              "agave-syscalls", "solana-sbpf"}
    versions = {item["name"]: item["version"] for item in packages
                if item["name"] in wanted}
    per_program: dict[str, list[int]] = {}
    for row in comparison.get("log_differences", []):
        if "recorded_consumed" not in row:
            continue
        difference = row["local_consumed"] - row["recorded_consumed"]
        per_program.setdefault(row["program_id"], []).append(difference)
    first = comparison.get("first_log_difference") or {}
    first_budget_gap = (first.get("local_remaining_budget", 0) -
                        first.get("recorded_remaining_budget", 0)
                        if "local_remaining_budget" in first else None)
    report = {"kind": "historical_runtime_gap_audit",
              "fixture": str(fixture_path), "comparison": str(comparison_path),
              "signature": origin.get("signature"),
              "transaction_slot": origin.get("transaction_slot"),
              "local_runtime_versions": versions,
              "historical_inputs": {
                  "program_version_verified": origin.get("program_version_verified", False),
                  "pinned_program_count": 1 + len(fixture.get("extra_programs", [])),
                  "clock_pinned": bool(origin.get("clock_sysvar_base64")),
                  "sysvars_pinned": sorted(origin.get("sysvars_base64", {})),
                  "feature_activation_count": len(origin.get("feature_activation_slots", {})),
                  "feature_snapshot_source": origin.get("feature_snapshot"),
                  "full_transaction_bytes_pinned": bool(fixture.get("transaction_base64")),
                  "state_exact": origin.get("state_exact", False)},
              "recorded_compute_units": comparison.get("recorded_compute_units"),
              "local_compute_units": comparison.get("local_compute_units"),
              "compute_unit_difference": comparison.get("compute_unit_difference"),
              "first_budget_gap": first_budget_gap,
              "first_divergent_log_index": first.get("index"),
              "nested_consumed_differences": per_program,
              "interpretation": (
                  "The first visible remaining-budget gap is already present at a nested call. "
                  "Compare parent execution and invocation overhead before changing nested program logic."
                  if first_budget_gap else
                  "The first differing log does not expose a remaining-budget gap."),
              "unresolved_inputs": [
                  "Historical validator Agave binary, enabled feature set including removed accounts, and program-cache state are not pinned.",
                  "The local runner uses current LiteSVM and Agave crates, not the validator's historical runtime.",
                  "Log-level attribution cannot identify the exact instruction that spent the gap."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "compute_unit_difference": report["compute_unit_difference"],
            "first_budget_gap": first_budget_gap,
            "nested_consumed_differences": per_program}


def compare_replay_with_transaction(fixture: dict, replay: dict,
                                    transaction: dict) -> dict:
    """Show where an isolated local run differs from the recorded full transaction."""
    origin = fixture["origin"]
    need(origin.get("signature") == replay["origin"].get("signature"),
         "fixture and replay report have different transaction signatures")
    need(fixture["program"]["sha256"] == replay["program"]["sha256"],
         "fixture and replay report pin different ELF hashes")
    need(transaction is not None and transaction["slot"] == origin["transaction_slot"],
         "transaction missing or slot differs from fixture")
    message = transaction["transaction"]["message"]
    meta = transaction["meta"]
    loaded = meta.get("loadedAddresses") or {}
    keys = message["accountKeys"] + loaded.get("writable", []) + loaded.get("readonly", [])
    pre = {row["accountIndex"]: int(row["uiTokenAmount"]["amount"])
           for row in meta.get("preTokenBalances") or []}
    post = {row["accountIndex"]: int(row["uiTokenAmount"]["amount"])
            for row in meta.get("postTokenBalances") or []}
    local = replay["scenarios"][0]
    need(local["name"] == "baseline", "replay report has no baseline first")
    token_programs = {KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"],
                      KNOWN_PROGRAM_IDS["SOLANA_TOKEN_2022_PROGRAM_ID"]}
    tracked = {pubkey for pubkey, record in fixture["accounts"].items()
               if record is not None and record["owner"] in token_programs and
               len(base64.b64decode(record["data_base64"], validate=True)) >= 72}
    comparisons = {}
    for index in sorted(pre.keys() & post.keys()):
        need(index < len(keys), "transaction token balance index is out of range")
        pubkey = keys[index]
        if pubkey not in tracked:
            continue
        actual_delta = post[index] - pre[index]
        change = local["changes"].get(pubkey)
        local_delta = (change["effect"].get("spl_token_amount_delta") if change else 0)
        if not local["success"]:
            local_delta = None
        comparisons[pubkey] = {
            "actual_full_transaction_delta": actual_delta,
            "local_isolated_instruction_delta": local_delta,
            "difference": local_delta - actual_delta if local_delta is not None else None,
        }
    need(comparisons, "no tracked SPL token accounts have transaction pre and post balances")
    different = {key: value for key, value in comparisons.items()
                 if value["difference"] != 0}
    target = target_token_transfer_deltas(transaction, origin, keys, fixture["program"]["id"])
    target_comparisons = None
    target_different = None
    if target is not None:
        target_comparisons = {}
        for pubkey in sorted(tracked):
            change = local["changes"].get(pubkey)
            local_delta = (change["effect"].get("spl_token_amount_delta") if change else 0)
            if not local["success"]:
                local_delta = None
            target_delta = target["token_deltas"].get(pubkey, 0)
            target_comparisons[pubkey] = {
                "recorded_target_transfer_delta": target_delta,
                "local_isolated_instruction_delta": local_delta,
                "difference": local_delta - target_delta if local_delta is not None else None,
            }
        target_different = {key: value for key, value in target_comparisons.items()
                            if value["difference"] != 0}
    return {
        "schema_version": 1, "kind": "isolated_replay_reconciliation",
        "signature": origin["signature"], "transaction_slot": origin["transaction_slot"],
        "program_id": fixture["program"]["id"],
        "program_sha256": fixture["program"]["sha256"],
        "program_version_verified": origin.get("program_version_verified", False),
        "account_state_source": origin.get("account_state_source"),
        "actual_transaction_error": meta.get("err"),
        "local_baseline_success": local["success"], "local_baseline_error": local["error"],
        "outer_instruction_count": len(message["instructions"]),
        "selected_outer_instruction_index": origin.get("instruction_index"),
        "selected_inner_instruction_index": origin.get("inner_index"),
        "token_account_comparisons": comparisons,
        "different_token_accounts": different,
        "all_tracked_token_deltas_match": local["success"] and not different,
        "target_call_transfers": target,
        "target_transfer_comparisons": target_comparisons,
        "different_target_transfer_deltas": target_different,
        "all_target_transfer_deltas_match": (
            local["success"] and not target_different if target is not None else None),
        "limitations": [
            "Actual token deltas cover the full transaction. The local baseline runs only the selected instruction.",
            "Target-call deltas decode SPL Token Transfer and TransferChecked CPI instructions only; mint, burn, fees, and other token operations are not included.",
            "A difference can come from parent instructions, CPI context, other transaction instructions, runtime differences, or account changes earlier in the slot.",
            "Matching token deltas alone does not prove all account data, logs, or compute use match.",
        ],
    }


def reconcile_replay(fixture_path: Path, replay_path: Path, output: Path,
                     rpc_env: str) -> dict:
    fixture = json.loads(fixture_path.read_text())
    replay = json.loads(replay_path.read_text())
    origin = fixture["origin"]
    need(origin.get("signature") and origin.get("transaction_slot") is not None,
         "fixture needs an original transaction signature and slot")
    url = os.environ.get(rpc_env, "")
    need(url.startswith("https://"),
         f"environment variable {rpc_env} must contain an HTTPS RPC URL")
    transaction = rpc(url, "getTransaction", [origin["signature"], {
        "encoding": "json", "commitment": "finalized",
        "maxSupportedTransactionVersion": 1,
    }])
    if origin.get("replay_mode") == "full_transaction":
        result = compare_full_runtime(fixture, replay, transaction)
    else:
        result = compare_replay_with_transaction(fixture, replay, transaction)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    if origin.get("replay_mode") == "full_transaction":
        return {"report": str(output),
                "compute_unit_difference": result["compute_unit_difference"],
                "first_log_difference": result["first_log_difference"],
                "log_difference_count": len(result["log_differences"])}
    return {"report": str(output),
            "all_tracked_token_deltas_match": result["all_tracked_token_deltas_match"],
            "different_token_accounts": result["different_token_accounts"],
            "all_target_transfer_deltas_match": result["all_target_transfer_deltas_match"],
            "different_target_transfer_deltas": result["different_target_transfer_deltas"]}


def replay_fixture(path: Path, output: Path, runner: Path, trace_dir: Path | None = None,
                   include_account_data: bool = False) -> dict:
    need(runner.exists(), f"replay runner missing: {runner}; build replay/Cargo.toml first")
    environment = os.environ.copy()
    if trace_dir is not None:
        trace_dir = trace_dir.resolve()
        need(not trace_dir.exists() or not any(trace_dir.iterdir()),
             f"trace directory must be empty: {trace_dir}")
        trace_dir.mkdir(parents=True, exist_ok=True)
        environment["SBF_TRACE_DIR"] = str(trace_dir)
    else:
        environment.pop("SBF_TRACE_DIR", None)
    if include_account_data:
        environment["SOLDECOMP_INCLUDE_ACCOUNT_DATA"] = "1"
    else:
        environment.pop("SOLDECOMP_INCLUDE_ACCOUNT_DATA", None)
    completed = subprocess.run([str(runner.resolve()), str(path.resolve())],
                               text=True, capture_output=True, check=False,
                               env=environment)
    need(completed.returncode == 0,
         f"replay runner failed: {completed.stderr.strip() or completed.stdout.strip()}")
    report = json.loads(completed.stdout)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "trace_dir": str(trace_dir) if trace_dir else None,
            "program_sha256": report["program"]["sha256"],
            "scenarios": [{"name": item["name"], "success": item["success"],
                           "error": item["error"],
                           "compute_units": item["compute_units"]}
                          for item in report["scenarios"]],
            "changed_outcome": report["changed_outcome"],
            "limitations": report["limitations"]}


def trace_execution(elf_path: Path, trace_dir: Path, addresses: list[int],
                    radius: int, max_visits: int, fixture_path: Path | None = None) -> dict:
    """Map LiteSVM register-trace PCs to addresses in a pinned ELF."""
    need(addresses, "at least one --address is required")
    need(radius >= 0 and max_visits > 0, "--radius must be non-negative and --max-visits positive")
    raw = elf_path.read_bytes()
    elf = ELF(raw)
    need(elf.text is not None, "ELF has no .text section")
    digest = hashlib.sha256(raw).hexdigest()
    text_bytes = elf.section_data(elf.text)
    token_amounts: dict[int, list[dict]] = {}
    if fixture_path is not None:
        fixture = json.loads(fixture_path.read_text())
        programs = [fixture["program"]] + fixture.get("extra_programs", [])
        need(any(program["sha256"] == digest for program in programs),
             "fixture does not pin the supplied ELF hash")
        account_indices: dict[str, list[int]] = {}
        for index, meta in enumerate(fixture["instruction"]["accounts"]):
            account_indices.setdefault(meta["pubkey"], []).append(index)
        for scenario in [None] + fixture.get("mutations", []):
            name = scenario["name"] if scenario else "baseline"
            for pubkey, record in fixture["accounts"].items():
                if record is None or record["owner"] not in (KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"],
                                           KNOWN_PROGRAM_IDS["SOLANA_TOKEN_2022_PROGRAM_ID"]):
                    continue
                data = bytearray(base64.b64decode(record["data_base64"], validate=True))
                if len(data) < 165:
                    continue
                if scenario and scenario.get("account") == pubkey and "data_base64" in scenario:
                    patch = base64.b64decode(scenario["data_base64"], validate=True)
                    offset = scenario["offset"]
                    need(0 <= offset <= len(data) - len(patch),
                         f"mutation {name} exceeds account data")
                    data[offset:offset + len(patch)] = patch
                amount = struct.unpack_from("<Q", data, 64)[0]
                if amount:
                    token_amounts.setdefault(amount, []).append(
                        {"scenario": name, "account": pubkey,
                         "instruction_account_indices": account_indices.get(pubkey, []),
                         "field": "spl_token_amount"})
    targets = set(addresses)
    for address in targets:
        need(elf.text.address <= address < elf.text.address + elf.text.size and
             (address - elf.text.address) % 8 == 0,
             f"address {address:#x} is not an aligned instruction in .text")
    traces = []
    for path in sorted(trace_dir.glob("*.regs")):
        hash_path = path.with_suffix(".exec.sha256")
        if not hash_path.exists() or hash_path.read_text().strip() != digest:
            continue
        instruction_path = path.with_suffix(".insns")
        program_path = path.with_suffix(".program_id")
        need(instruction_path.exists() and program_path.exists(),
             f"incomplete register trace: {path}")
        data = path.read_bytes()
        instructions = instruction_path.read_bytes()
        need(len(data) % 96 == 0 and len(instructions) == len(data) // 12,
             f"invalid trace lengths: {path}")
        records = list(struct.iter_unpack("<12Q", data))
        hits = []
        counts = {f"{address:#x}": 0 for address in sorted(targets)}
        for index, registers in enumerate(records):
            address = elf.text.address + registers[11] * 8
            if address not in targets:
                continue
            counts[f"{address:#x}"] += 1
            if len(hits) >= max_visits:
                continue
            context = []
            for position in range(max(0, index - radius), min(len(records), index + radius + 1)):
                row = records[position]
                pc_address = elf.text.address + row[11] * 8
                insn = instructions[position * 8:position * 8 + 8]
                opcode, packed_registers, displacement, immediate = INSN.unpack(insn)
                offset_in_text = pc_address - elf.text.address
                context.append({"step": position, "address": f"{pc_address:#x}",
                                "instruction_hex": insn.hex(),
                                "register_lift": lift(Instruction(
                                    pc_address, opcode, packed_registers & 15,
                                    packed_registers >> 4, displacement, immediate), {}),
                                "matches_elf_instruction": (
                                    0 <= offset_in_text <= elf.text.size - 8 and
                                    text_bytes[offset_in_text:offset_in_text + 8] == insn),
                                "registers": {f"r{number}": f"{value:#x}"
                                              for number, value in enumerate(row[:11])}})
            register_matches = []
            for number, value in enumerate(registers[:11]):
                for candidate in token_amounts.get(value, []):
                    register_matches.append({"register": f"r{number}", "value": value,
                                             **candidate})
            hits.append({"step": index, "address": f"{address:#x}",
                         "token_amount_matches": register_matches, "context": context})
        traces.append({"file": str(path), "program_id": program_path.read_text().strip(),
                       "steps": len(records), "visits": counts,
                       "sampled_hits": hits})
    need(traces, f"no trace in {trace_dir} matches ELF SHA-256 {digest}")
    return {"elf": str(elf_path), "elf_sha256": digest,
            "fixture": str(fixture_path) if fixture_path else None,
            "text_address": f"{elf.text.address:#x}",
            "pc_mapping": "ELF .text address + PC * 8",
            "addresses": [f"{address:#x}" for address in sorted(targets)],
            "max_sampled_hits_per_trace": max_visits, "traces": traces}


def trace_memory_provenance(before: list[tuple[int, ...]],
                            after: list[tuple[int, ...]],
                            code: dict[int, Instruction], imports: dict[int, str],
                            text_address: int, old_value: int, new_value: int,
                            max_events: int = 250) -> dict:
    """Follow differential loads through registers and exact virtual memory addresses."""
    def visits(rows: list[tuple[int, ...]]) -> dict[tuple[int, int], tuple[int, tuple[int, ...]]]:
        counts: dict[int, int] = {}
        result = {}
        for index, row in enumerate(rows):
            pc = row[11]
            counts[pc] = counts.get(pc, 0) + 1
            result[(pc, counts[pc])] = (index, row)
        return result

    left, right = visits(before), visits(after)
    roots = []
    for key, (index, row) in left.items():
        match = right.get(key)
        if match is None or index + 1 >= len(before) or match[0] + 1 >= len(after):
            continue
        address = text_address + key[0] * 8
        ins = code.get(address)
        if ins is None or ins.opcode & 7 != 1 or ins.src > 10:
            continue
        other_index, other = match
        width = SIZES.get(ins.opcode & 0x18)
        if not width or width < 8:
            continue
        if (before[index + 1][ins.dst] == old_value and
                after[other_index + 1][ins.dst] == new_value and
                row[ins.src] + ins.offset == other[ins.src] + ins.offset):
            roots.append({"key": key, "step": index, "address": address,
                          "virtual_address": row[ins.src] + ins.offset,
                          "width": width, "register": ins.dst})

    if not roots:
        return {"root_loads": [], "events": [], "cpi_candidates": [],
                "confidence": "no_differential_memory_load"}
    # A single input can be read repeatedly. Each root starts an independent
    # lineage so stores and reloads cannot be mistaken for unrelated copies.
    events = []
    cpi_candidates = []
    cpi_boundaries = []
    indexed_right = {key: value[1] for key, value in right.items()}
    counts: dict[int, int] = {}
    root_keys = {tuple(item["key"]): item for item in roots}
    actual_roots = []
    tainted_regs: set[int] = set()
    tainted_memory: set[int] = set()
    memory_values: dict[int, int] = {}
    register_source: dict[int, int] = {}
    memory_source: dict[int, int] = {}
    event_count = 0

    def emit(event: dict) -> int:
        nonlocal event_count
        event_count += 1
        event["id"] = event_count
        if len(events) < max_events:
            events.append(event)
        return event_count

    def stored_word(location: int) -> int | None:
        values = [memory_values.get(location + byte) for byte in range(8)]
        if any(value is None for value in values):
            return None
        return int.from_bytes(bytes(values), "little")

    for step, row in enumerate(before):
        pc = row[11]
        counts[pc] = counts.get(pc, 0) + 1
        key = (pc, counts[pc])
        address = text_address + pc * 8
        ins = code.get(address)
        if ins is None:
            continue
        cls = ins.opcode & 7
        root = root_keys.get(key)
        same = indexed_right.get(key)
        if cls == 1:
            width = SIZES.get(ins.opcode & 0x18, 0)
            location = row[ins.src] + ins.offset
            from_memory = any(location + byte in tainted_memory for byte in range(width))
            source = root is not None or from_memory
            parents = sorted({memory_source[location + byte] for byte in range(width)
                              if location + byte in memory_source})
            tainted_regs.discard(ins.dst)
            register_source.pop(ins.dst, None)
            if source:
                tainted_regs.add(ins.dst)
                if root and not from_memory:
                    actual_roots.append(root)
                event_id = emit({"step": step, "address": f"{address:#x}",
                                 "kind": "memory_reload" if from_memory else "source_load",
                                 "virtual_address": f"{location:#x}", "width": width,
                                 "register": f"r{ins.dst}", "parents": parents,
                                 "baseline_value": before[step + 1][ins.dst] if step + 1 < len(before) else None,
                                 "mutated_value": (after[right[key][0] + 1][ins.dst]
                                                   if key in right and right[key][0] + 1 < len(after)
                                                   else None),
                                 "differential_value": bool(same and
                                      row[ins.src] == same[ins.src])})
                register_source[ins.dst] = event_id
                if root:
                    value = before[step + 1][ins.dst] if step + 1 < len(before) else 0
                    for byte, content in enumerate(value.to_bytes(8, "little")[:width]):
                        memory_values[location + byte] = content
                        tainted_memory.add(location + byte)
                        memory_source[location + byte] = event_id
        elif cls in (2, 3):
            width = SIZES.get(ins.opcode & 0x18, 0)
            location = row[ins.dst] + ins.offset
            tagged = cls == 3 and ins.src in tainted_regs
            value = row[ins.src] if cls == 3 else ins.imm
            value_bytes = (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
            for byte in range(width):
                memory_values[location + byte] = value_bytes[byte]
                if tagged:
                    tainted_memory.add(location + byte)
                else:
                    tainted_memory.discard(location + byte)
                    memory_source.pop(location + byte, None)
            if tagged:
                event_id = emit({"step": step, "address": f"{address:#x}",
                                 "kind": "memory_store", "virtual_address": f"{location:#x}",
                                 "width": width, "register": f"r{ins.src}",
                                 "parents": [register_source[ins.src]] if ins.src in register_source else [],
                                 "value": value})
                for byte in range(width):
                    memory_source[location + byte] = event_id
        elif cls in (4, 7):
            operation = ins.opcode & 0xF0
            source_reg = ins.src if ins.opcode & 8 else None
            source_tagged = source_reg in tainted_regs if source_reg is not None else False
            destination_tagged = operation != 0xB0 and ins.dst in tainted_regs
            parents = sorted({register_source[reg] for reg in (ins.dst, source_reg)
                              if reg is not None and reg in register_source and
                              (reg != ins.dst or destination_tagged)})
            tagged = source_tagged or destination_tagged
            tainted_regs.discard(ins.dst)
            register_source.pop(ins.dst, None)
            if tagged:
                tainted_regs.add(ins.dst)
                following = before[step + 1][ins.dst] if step + 1 < len(before) else None
                other_step = right.get(key, (None, None))[0]
                other_value = (after[other_step + 1][ins.dst] if other_step is not None and
                               other_step + 1 < len(after) else None)
                register_source[ins.dst] = emit({"step": step, "address": f"{address:#x}",
                                                 "kind": "arithmetic", "operation": OPS.get(operation, "unknown"),
                                                 "width_bits": 64 if cls == 7 else 32,
                                                 "destination": f"r{ins.dst}", "parents": parents,
                                                 "baseline_input": row[ins.dst],
                                                 "baseline_rhs": row[ins.src] if source_reg is not None else ins.imm,
                                                 "baseline_output": following,
                                                 "mutated_output": other_value})
        elif ins.opcode == 0x18:
            tainted_regs.discard(ins.dst)
            register_source.pop(ins.dst, None)
        elif cls in (5, 6) and ins.opcode & 0xF0 in JMPS:
            source_reg = ins.src if ins.opcode & 8 else None
            parents = sorted({register_source[reg] for reg in (ins.dst, source_reg)
                              if reg is not None and reg in register_source})
            if parents:
                emit({"step": step, "address": f"{address:#x}",
                      "kind": "tainted_branch", "comparison": JMPS[ins.opcode & 0xF0],
                      "baseline_left": row[ins.dst],
                      "baseline_right": row[ins.src] if source_reg is not None else ins.imm,
                      "parents": parents})
        elif cls in (5, 6) and ins.opcode & 0xF0 == 0x80:
            callee = imports.get(address)
            if callee and any(callee.startswith(prefix) for prefix in
                              ("sol_memcpy", "sol_memmove", "sol_memset")):
                destination, length = row[1], row[3]
                if 0 < length <= 1_000_000:
                    if callee.startswith("sol_memset"):
                        contents = [row[2] & 0xFF] * length
                        sources = [register_source.get(2)] * length
                    else:
                        contents = [memory_values.get(row[2] + byte) for byte in range(length)]
                        sources = [memory_source.get(row[2] + byte) for byte in range(length)]
                    parents = sorted({source for source in sources if source is not None})
                    event_id = emit({"step": step, "address": f"{address:#x}",
                                     "kind": "memory_syscall", "callee": callee,
                                     "destination": f"{destination:#x}", "length": length,
                                     "known_source_bytes": sum(value is not None for value in contents),
                                     "tainted_source_bytes": sum(source is not None for source in sources),
                                     "parents": parents}) if parents else None
                    for byte, content in enumerate(contents):
                        location = destination + byte
                        if content is None:
                            memory_values.pop(location, None)
                        else:
                            memory_values[location] = content
                        if sources[byte] is None:
                            tainted_memory.discard(location)
                            memory_source.pop(location, None)
                        else:
                            tainted_memory.add(location)
                            memory_source[location] = event_id
            if callee and "invoke_signed" in callee:
                pointer = row[1]
                nearby = sorted(item for item in tainted_memory
                                if pointer <= item < pointer + 64)
                data_pointer = stored_word(pointer + 24) if callee.endswith("_c") else None
                data_length = stored_word(pointer + 32) if callee.endswith("_c") else None
                linked_data = (data_pointer is not None and data_length is not None and
                               0 < data_length <= 1_000_000)
                linked_bytes = (sum(data_pointer <= item < data_pointer + data_length
                                    for item in tainted_memory) if linked_data else 0)
                boundary = {"step": step, "address": f"{address:#x}",
                            "callee": callee, "instruction_pointer": f"{pointer:#x}",
                            "tainted_nearby_bytes": len(nearby),
                            "data_pointer": f"{data_pointer:#x}" if linked_data else None,
                            "data_length": data_length if linked_data else None,
                            "tainted_instruction_data_bytes": linked_bytes,
                            "value_parent_events": sorted({memory_source[item] for item in tainted_memory
                                                           if linked_data and data_pointer <= item < data_pointer + data_length
                                                           and item in memory_source}),
                            "tainted_argument_registers":
                                [f"r{reg}" for reg in range(1, 6)
                                 if reg in tainted_regs]}
                if actual_roots:
                    cpi_boundaries.append(boundary)
                if nearby or linked_bytes or any(reg in tainted_regs for reg in range(1, 6)):
                    cpi_candidates.append(boundary)
            tainted_regs.discard(0)
            register_source.pop(0, None)
    return {"root_loads": [{key: value for key, value in item.items() if key != "key"}
                           for item in actual_roots],
            "events": events, "cpi_boundaries": cpi_boundaries,
            "cpi_candidates": cpi_candidates,
            "truncated": event_count > max_events, "total_events": event_count,
            "confidence": "dynamic_register_and_memory_lineage_with_explicit_gaps"}


def resolve_sbf_input_account(fixture: dict, virtual_address: int,
                              width: int) -> dict | None:
    """Map an input-region address using the serialized instruction account layout."""
    input_start = 0x400000000
    if virtual_address < input_start or width <= 0:
        return None
    offset = virtual_address - input_start
    cursor = 8  # u64 account count
    seen: set[str] = set()
    for index, meta in enumerate(fixture["instruction"]["accounts"]):
        pubkey = meta["pubkey"]
        if pubkey in seen:
            cursor += 8  # duplicate marker and padding
            continue
        seen.add(pubkey)
        record = fixture["accounts"].get(pubkey)
        if record is None:
            return {"unresolved_after_account_index": index,
                    "reason": "account data length is absent from fixture"}
        raw = base64.b64decode(record["data_base64"], validate=True)
        data_start = cursor + 88
        if data_start <= offset and offset + width <= data_start + len(raw):
            return {"account": pubkey, "account_index": index,
                    "account_data_offset": offset - data_start,
                    "layout_source": "captured_instruction_account_lengths"}
        cursor = (data_start + len(raw) + 10240 + 8 + 7) & ~7
    return None



def discover_fields(path: Path, output: Path, runner: Path) -> dict:
    """Catalog account fields read by the pinned ELF, without declared field offsets."""
    fixture = json.loads(path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported replay fixture schema")
    elf_path = (path.parent / fixture["program"]["elf"]).resolve()
    elf_bytes = elf_path.read_bytes()
    digest = hashlib.sha256(elf_bytes).hexdigest()
    need(digest == fixture["program"]["sha256"], "fixture ELF hash mismatch")
    elf = ELF(elf_bytes)
    code = {item.address: item for item in instructions(elf)}
    roles = inspect_fixture(path)
    role_by_account = {item["pubkey"]: item for item in roles["instruction_accounts"]}
    output.parent.mkdir(parents=True, exist_ok=True)
    trace_dir = Path(tempfile.mkdtemp(prefix=output.stem + "-registers-",
                                      dir=output.parent))
    replay_path = output.parent / (output.stem + "-replay.json")
    replay_fixture(path, replay_path, runner, trace_dir, include_account_data=True)
    replay = json.loads(replay_path.read_text())
    fields: dict[tuple[str, int, int], dict] = {}
    trace_rows = []
    for trace in sorted(trace_dir.glob("*.regs")):
        hash_path = trace.with_suffix(".exec.sha256")
        if not hash_path.exists() or hash_path.read_text().strip() != digest:
            continue
        raw = trace.read_bytes()
        need(len(raw) % 96 == 0, f"malformed register trace {trace}")
        rows = list(struct.iter_unpack("<12Q", raw))
        mapped = 0
        for step, row in enumerate(rows[:-1]):
            address = elf.text.address + row[11] * 8
            ins = code.get(address)
            if ins is None or ins.opcode & 7 != 1 or ins.src > 10:
                continue
            width = SIZES.get(ins.opcode & 0x18, 0)
            if width not in (1, 2, 4, 8):
                continue
            location = row[ins.src] + ins.offset
            mapping = resolve_sbf_input_account(fixture, location, width)
            if not mapping or "account" not in mapping:
                continue
            mapped += 1
            pubkey, offset = mapping["account"], mapping["account_data_offset"]
            key = (pubkey, offset, width)
            if key not in fields:
                role = role_by_account.get(pubkey, {})
                known = None
                if "token_account" in role:
                    known = {64: "spl_token_amount", 108: "spl_token_state"}.get(offset)
                elif "mint" in role:
                    known = {36: "spl_mint_supply", 44: "spl_mint_decimals"}.get(offset)
                fields[key] = {"account": pubkey, "account_index": mapping["account_index"],
                               "offset": offset, "width": width,
                               "owner": role.get("owner"), "role_hints": role.get("hints", []),
                               "known_field": known, "read_count": 0,
                               "first_instruction": f"{address:#x}",
                               "sample_values": []}
            field = fields[key]
            field["read_count"] += 1
            value = rows[step + 1][ins.dst]
            if value not in field["sample_values"] and len(field["sample_values"]) < 4:
                field["sample_values"].append(value)
        trace_rows.append({"trace": str(trace), "steps": len(rows),
                           "mapped_account_loads": mapped})
    need(trace_rows, f"no target-program trace matches ELF SHA-256 {digest}")
    baseline = replay["scenarios"][0]
    for field in fields.values():
        change = baseline["changes"].get(field["account"])
        if not change or not change["before"] or not change["after"]:
            field["changed_after_replay"] = False
            continue
        before_b64 = change["before"].get("data_base64")
        after_b64 = change["after"].get("data_base64")
        if before_b64 is None or after_b64 is None:
            field["changed_after_replay"] = None
            continue
        before = base64.b64decode(before_b64)
        after = base64.b64decode(after_b64)
        start, end = field["offset"], field["offset"] + field["width"]
        field["changed_after_replay"] = (before[start:end] != after[start:end])
    catalog = sorted(fields.values(), key=lambda item:
                     (item["account_index"], item["offset"], item["width"]))
    report = {"kind": "observed_account_field_catalog", "fixture": str(path),
              "program_id": fixture["program"]["id"], "program_sha256": digest,
              "baseline_success": baseline["success"], "account_roles": roles["instruction_accounts"],
              "fields": catalog, "traces": trace_rows,
              "limitations": ["A field is listed only when this replay executed a direct SBF load from the serialized account data.",
                              "Offsets and widths are observed; labels outside known SPL layouts remain hypotheses.",
                              "A register load alone does not establish the field's meaning or attacker control.",
                              "For CPI and full-transaction traces, account mapping assumes the selected instruction account layout matches the traced invocation."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "fields": len(catalog),
            "mapped_account_loads": sum(item["mapped_account_loads"] for item in trace_rows),
            "traces": len(trace_rows)}


def capture_cpi_instruction_data(rows: list[tuple[int, ...]],
                                 code: dict[int, Instruction],
                                 imports: dict[int, str],
                                 text_address: int) -> list[dict]:
    """Recover C CPI data only when every instruction byte has a traced store."""
    memory: dict[int, int] = {}
    visits: dict[int, int] = {}
    calls = []

    def word(location: int) -> int | None:
        values = [memory.get(location + byte) for byte in range(8)]
        return None if any(value is None for value in values) else int.from_bytes(bytes(values), "little")

    for step, row in enumerate(rows):
        pc = row[11]
        address = text_address + pc * 8
        ins = code.get(address)
        if ins is None:
            continue
        cls = ins.opcode & 7
        if cls in (2, 3):
            width = SIZES.get(ins.opcode & 0x18, 0)
            location = row[ins.dst] + ins.offset
            value = row[ins.src] if cls == 3 else ins.imm
            raw = (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
            for byte, content in enumerate(raw):
                memory[location + byte] = content
        elif cls in (5, 6) and ins.opcode & 0xF0 == 0x80:
            callee = imports.get(address)
            if callee and any(callee.startswith(prefix) for prefix in
                              ("sol_memcpy", "sol_memmove", "sol_memset")):
                destination, length = row[1], row[3]
                if 0 < length <= 1_000_000:
                    copied = ([row[2] & 0xFF] * length if callee.startswith("sol_memset")
                              else [memory.get(row[2] + byte) for byte in range(length)])
                    for byte, content in enumerate(copied):
                        if content is None:
                            memory.pop(destination + byte, None)
                        else:
                            memory[destination + byte] = content
            if callee != "sol_invoke_signed_c":
                continue
            visits[address] = visits.get(address, 0) + 1
            instruction_ptr = row[1]
            data_ptr, data_len = word(instruction_ptr + 24), word(instruction_ptr + 32)
            data = None
            if data_ptr is not None and data_len is not None and 0 < data_len <= 4096:
                values = [memory.get(data_ptr + byte) for byte in range(data_len)]
                if all(value is not None for value in values):
                    data = bytes(values)
            calls.append({"step": step, "address": f"{address:#x}",
                          "visit": visits[address], "callee": callee,
                          "data_hex": data.hex() if data is not None else None,
                          "data_length": data_len,
                          "spl_token_transfer_amount": (
                              int.from_bytes(data[1:9], "little")
                              if data is not None and len(data) == 9 and data[0] in (3, 12)
                              else None)})
    return calls


def trace_roles(path: Path, name: str, output: Path, runner: Path,
                flow_path: Path | None) -> dict:
    """Find register values that move with one mutated token account amount."""
    fixture = json.loads(path.read_text())
    matches = [item for item in fixture.get("mutations", []) if item["name"] == name]
    need(len(matches) == 1, f"mutation {name} is missing or duplicated")
    mutation = matches[0]
    pubkey = mutation["account"]
    record = fixture["accounts"].get(pubkey)
    need(record is not None and mutation.get("data_base64") is not None,
         "trace-roles requires an existing account byte mutation")
    original = bytearray(base64.b64decode(record["data_base64"], validate=True))
    need(len(original) >= 165 and record["owner"] in {
        KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"],
        KNOWN_PROGRAM_IDS["SOLANA_TOKEN_2022_PROGRAM_ID"]},
         "trace-roles requires a standard SPL token account")
    changed = original.copy()
    replacement = base64.b64decode(mutation["data_base64"], validate=True)
    offset = mutation.get("offset", 0)
    need(0 <= offset <= len(changed) - len(replacement), "mutation is out of bounds")
    changed[offset:offset + len(replacement)] = replacement
    old_amount = struct.unpack_from("<Q", original, 64)[0]
    new_amount = struct.unpack_from("<Q", changed, 64)[0]
    need(old_amount != new_amount, "mutation does not change the token amount")
    elf_path = (path.parent / fixture["program"]["elf"]).resolve()
    elf_data = elf_path.read_bytes()
    elf = ELF(elf_data)
    digest = hashlib.sha256(elf_data).hexdigest()
    need(digest == fixture["program"]["sha256"], "fixture ELF hash mismatch")
    flow_events: dict[str, list[dict]] = {}
    if flow_path is not None:
        flow = json.loads(flow_path.read_text())
        need(flow.get("input_sha256") == digest, "flow report is for a different ELF")
        for function in flow.get("functions", []):
            for event in function.get("events", []):
                flow_events.setdefault(event["address"], []).append({
                    "function": function["address"], "kind": event.get("kind"),
                    "op": event.get("op")})
    output.parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=output.stem + "-trace-",
                                      dir=output.parent))
    baseline_fixture = directory / "baseline.json"
    mutated_fixture = directory / "mutated.json"
    baseline_report = directory / "baseline-report.json"
    mutated_report = directory / "mutated-report.json"
    for destination, apply_mutation in ((baseline_fixture, False),
                                        (mutated_fixture, True)):
        copy = json.loads(path.read_text())
        copy["mutations"] = []
        if apply_mutation:
            copy["accounts"][pubkey]["data_base64"] = base64.b64encode(changed).decode()
        for program in [copy["program"]] + copy.get("extra_programs", []):
            program["elf"] = os.path.relpath((path.parent / program["elf"]).resolve(),
                                             destination.parent.resolve())
        destination.write_text(json.dumps(copy, indent=2) + "\n")
    baseline_dir = directory / "baseline-registers"
    mutated_dir = directory / "mutated-registers"
    replay_fixture(baseline_fixture, baseline_report, runner, baseline_dir)
    replay_fixture(mutated_fixture, mutated_report, runner, mutated_dir)

    def load_trace(folder: Path) -> list[tuple[int, ...]]:
        matching = [candidate for candidate in folder.glob("*.regs")
                    if candidate.with_suffix(".exec.sha256").exists() and
                    candidate.with_suffix(".exec.sha256").read_text().strip() == digest]
        need(len(matching) == 1,
             f"expected one target-program invocation in {folder}; got {len(matching)}")
        raw = matching[0].read_bytes()
        need(len(raw) % 96 == 0, "malformed register trace")
        return list(struct.iter_unpack("<12Q", raw))

    before = load_trace(baseline_dir)
    after = load_trace(mutated_dir)
    def index_trace(rows: list[tuple[int, ...]]) -> dict[tuple[int, int], tuple[int, ...]]:
        visits: dict[int, int] = {}
        indexed = {}
        for row in rows:
            pc = row[11]
            visits[pc] = visits.get(pc, 0) + 1
            indexed[(pc, visits[pc])] = row
        return indexed
    earlier, later = index_trace(before), index_trace(after)
    program_instructions = {item.address: item for item in instructions(elf)}
    hits = []
    for (pc, visit), left in earlier.items():
        right = later.get((pc, visit))
        if right is None:
            continue
        address = elf.text.address + pc * 8
        ins = program_instructions.get(address)
        if ins is None:
            continue
        for register in range(11):
            if left[register] == old_amount and right[register] == new_amount:
                key = f"{address:#x}"
                hits.append({"address": key, "visit": visit,
                             "register": f"r{register}",
                             "instruction": lift(ins, {}),
                             "flow_events": flow_events.get(key, [])})
    baseline = json.loads(baseline_report.read_text())["scenarios"][0]
    mutated = json.loads(mutated_report.read_text())["scenarios"][0]
    provenance = trace_memory_provenance(before, after, program_instructions,
                                         elf.import_calls, elf.text.address,
                                         old_amount, new_amount)
    for root in provenance["root_loads"]:
        mapping = resolve_sbf_input_account(
            fixture, root["virtual_address"], root["width"])
        if mapping:
            root["input_account_mapping"] = mapping
            root["matches_mutated_field"] = (mapping.get("account") == pubkey and
                mapping.get("account_data_offset") == 64 and root["width"] == 8)
    baseline_calls = capture_cpi_instruction_data(
        before, program_instructions, elf.import_calls, elf.text.address)
    mutated_calls = capture_cpi_instruction_data(
        after, program_instructions, elf.import_calls, elf.text.address)
    by_call = {(item["address"], item["visit"]): item for item in mutated_calls}
    provenance["cpi_data_comparisons"] = [
        {"address": item["address"], "visit": item["visit"],
         "baseline_data_hex": item["data_hex"],
         "mutated_data_hex": by_call[(item["address"], item["visit"])]["data_hex"],
         "baseline_transfer_amount": item["spl_token_transfer_amount"],
         "mutated_transfer_amount": by_call[(item["address"], item["visit"])]["spl_token_transfer_amount"],
         "instruction_data_changed": item["data_hex"] !=
             by_call[(item["address"], item["visit"])]["data_hex"]}
        for item in baseline_calls if (item["address"], item["visit"]) in by_call]
    first_root_step = min((root["step"] for root in provenance["root_loads"]), default=None)
    provenance["first_control_flow_divergence_after_source"] = None
    if first_root_step is not None:
        root_pc = before[first_root_step][11]
        root_visit = sum(row[11] == root_pc for row in before[:first_root_step + 1])
        right_root = None
        right_visits = 0
        for index, row in enumerate(after):
            if row[11] == root_pc:
                right_visits += 1
                if right_visits == root_visit:
                    right_root = index
                    break
        if right_root is not None:
            for left_step, right_step in zip(range(first_root_step, len(before)),
                                             range(right_root, len(after))):
                if before[left_step][11] != after[right_step][11]:
                    provenance["first_control_flow_divergence_after_source"] = {
                        "baseline_step": left_step, "mutated_step": right_step,
                        "baseline_address": f"{elf.text.address + before[left_step][11] * 8:#x}",
                        "mutated_address": f"{elf.text.address + after[right_step][11] * 8:#x}"}
                    break
    provenance["changed_cpi_data_without_lineage"] = [
        {"address": item["address"], "visit": item["visit"]}
        for item in provenance["cpi_data_comparisons"]
        if item["instruction_data_changed"] and not any(
            boundary["address"] == item["address"] and
            boundary["tainted_instruction_data_bytes"] > 0
            for boundary in provenance["cpi_boundaries"])]
    report = {"kind": "differential_account_trace", "fixture": str(path),
              "program_id": fixture["program"]["id"], "program_sha256": digest,
              "mutation": name, "account": pubkey,
              "old_token_amount": old_amount, "new_token_amount": new_amount,
              "baseline_steps": len(before), "mutated_steps": len(after),
              "matched_sites": len(hits), "sites": hits[:200],
              "baseline_success": baseline["success"],
              "mutated_success": mutated["success"],
              "baseline_account_changes": baseline["changes"],
              "mutated_account_changes": mutated["changes"],
              "memory_provenance": provenance,
              "limitations": ["A matched load roots the changed value at a virtual memory address; account mapping assumes the captured instruction account lengths match the invocation.",
                              "Store-to-load links use exact virtual addresses within one invocation. CPI instruction bytes are reconstructed from traced stores; memory-copy syscalls or untraced writes can leave bytes unknown or stale.",
                              "Changed CPI bytes without tainted data-byte lineage are explicitly listed as unproven. A branch, unmodeled syscall, or unobserved memory write may bridge the gap.",
                              "If control flow diverges, matching by program counter and visit number may miss or mispair later steps.",
                              "Only one target-program invocation per scenario is supported."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "matched_sites": len(hits),
            "baseline_steps": len(before), "mutated_steps": len(after)}


def inspect_fixture(path: Path) -> dict:
    """Infer bounded account-role hints from a captured instruction fixture."""
    fixture = json.loads(path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported replay fixture schema")
    accounts = fixture["accounts"]
    metas = fixture["instruction"]["accounts"]
    program_id = fixture["program"]["id"]
    authorities: dict[str, list[int]] = {}
    records = []
    for index, meta in enumerate(metas):
        pubkey = meta["pubkey"]
        value = accounts.get(pubkey)
        info = {"index": index, "pubkey": pubkey,
                "is_signer": meta["is_signer"], "is_writable": meta["is_writable"],
                "owner": value["owner"] if value else None, "hints": []}
        if pubkey == "Sysvar1nstructions1111111111111111111111111":
            info["hints"].append("instructions_sysvar")
        if pubkey in KNOWN_PROGRAM_IDS.values():
            info["hints"].append("known_program_id")
        if value is None:
            info["hints"].append("missing_or_runtime_account")
        else:
            raw = base64.b64decode(value["data_base64"], validate=True)
            if value["owner"] == program_id:
                info["hints"].append("program_owned_state_candidate")
            if value["owner"] in {
                KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"],
                KNOWN_PROGRAM_IDS["SOLANA_TOKEN_2022_PROGRAM_ID"],
            }:
                if len(raw) >= 165 and raw[108] in (1, 2):
                    mint, authority = b58encode(raw[:32]), b58encode(raw[32:64])
                    info["token_account"] = {"mint": mint, "authority": authority,
                                             "amount": struct.unpack_from("<Q", raw, 64)[0]}
                    info["hints"].append("token_account")
                    authorities.setdefault(authority, []).append(index)
                    authority_record = accounts.get(authority)
                    if authority_record and authority_record["owner"] == program_id:
                        info["hints"].append("program_vault_candidate")
                    if any(item["pubkey"] == authority and item["is_signer"] for item in metas):
                        info["hints"].append("signer_owned_token_account_candidate")
                elif len(raw) >= 82 and raw[45] in (0, 1):
                    info["mint"] = {"supply": struct.unpack_from("<Q", raw, 36)[0],
                                    "decimals": raw[44]}
                    info["hints"].append("token_mint_candidate")
        records.append(info)
    signer_candidates = []
    for info in records:
        if info["pubkey"] in authorities:
            info["controls_token_account_indices"] = authorities[info["pubkey"]]
            authority_record = accounts.get(info["pubkey"])
            if (not info["is_signer"] and fixture["origin"].get("inner_index") is not None
                    and (authority_record is None or authority_record["owner"] != program_id)):
                info["hints"].append("possible_missing_cpi_signer")
                signer_candidates.append(info["pubkey"])
    return {"fixture": str(path), "program_id": program_id,
            "program_sha256": fixture["program"]["sha256"],
            "possible_missing_cpi_signers": list(dict.fromkeys(signer_candidates)),
            "instruction_accounts": records,
            "note": "Role hints follow account layout and ownership; validate them against program logic and transaction behavior."}


def probe_fixture(path: Path, output: Path, runner: Path,
                  basis_points: list[int], max_accounts: int) -> dict:
    """Run role-guided account changes and report behavioral hypotheses."""
    need(max_accounts > 0 and basis_points and
         all(0 < value <= 10000 for value in basis_points),
         "probe needs positive account limit and basis points from 1 to 10000")
    fixture = json.loads(path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported replay fixture schema")
    need(fixture["origin"].get("program_version_verified"),
         "probe requires a verified pinned program version")
    roles = inspect_fixture(path)
    candidates = [item for item in roles["instruction_accounts"]
                  if item.get("token_account") and item["is_writable"]]
    candidates.sort(key=lambda item: ("program_vault_candidate" not in item["hints"],
                                      item["index"]))
    candidates = candidates[:max_accounts]
    need(candidates, "no writable SPL token accounts in the selected instruction")
    generated = []
    for item in candidates:
        pubkey = item["pubkey"]
        amount = item["token_account"]["amount"]
        for bps in sorted(set(basis_points)):
            delta = max(1, amount * bps // 10000)
            for signed_delta in (delta, -delta):
                changed = amount + signed_delta
                if not 0 <= changed <= 2**64 - 1:
                    continue
                name = f"account-{item['index']}-{'plus' if signed_delta > 0 else 'minus'}-{bps}bp"
                generated.append({"name": name, "account": pubkey, "offset": 64,
                                  "data_base64": base64.b64encode(struct.pack("<Q", changed)).decode(),
                                  "input_amount": amount, "input_delta": signed_delta,
                                  "role_hints": item["hints"]})
    probe_path = output.with_suffix(".probe-fixture.json")
    replay_path = output.with_suffix(".probe-replay.json")
    for program in [fixture["program"]] + fixture.get("extra_programs", []):
        program["elf"] = os.path.relpath((path.parent / program["elf"]).resolve(),
                                         probe_path.parent.resolve())
    fixture["mutations"] = [{key: value for key, value in item.items()
                             if key in ("name", "account", "offset", "data_base64")}
                            for item in generated]
    probe_path.parent.mkdir(parents=True, exist_ok=True)
    probe_path.write_text(json.dumps(fixture, indent=2) + "\n")
    replay_fixture(probe_path, replay_path, runner)
    replay = json.loads(replay_path.read_text())
    baseline = replay["scenarios"][0]
    token_accounts = {item["pubkey"]: item["token_account"]
                      for item in roles["instruction_accounts"]
                      if item.get("token_account")}

    def effects(scenario: dict) -> dict[str, int]:
        return {pubkey: change["effect"]["spl_token_amount_delta"]
                for pubkey, change in scenario["changes"].items()
                if change["effect"]["spl_token_amount_delta"] is not None}

    baseline_effects = effects(baseline)
    scenarios = []
    hypotheses = []
    for item, scenario in zip(generated, replay["scenarios"][1:], strict=True):
        own_effects = effects(scenario)
        changed = {pubkey: {"baseline_delta": baseline_effects.get(pubkey, 0),
                            "mutated_delta": own_effects.get(pubkey, 0),
                            "difference": own_effects.get(pubkey, 0) - baseline_effects.get(pubkey, 0)}
                   for pubkey in sorted(baseline_effects.keys() | own_effects.keys())
                   if own_effects.get(pubkey, 0) != baseline_effects.get(pubkey, 0)}
        row = {"name": scenario["name"], "mutated_account": item["account"],
               "input_token_delta": item["input_delta"],
               "role_hints": item["role_hints"], "success": scenario["success"],
               "error": scenario["error"], "changed_token_effects": changed,
               "compute_units_difference": scenario["compute_units"] - baseline["compute_units"]}
        scenarios.append(row)
        if baseline["success"] and scenario["success"] and item["input_delta"] > 0:
            gains = [pubkey for pubkey, change in changed.items()
                     if change["difference"] > 0 and pubkey != item["account"]]
            if gains:
                hypotheses.append({"kind": "external_balance_changes_payout",
                                   "scenario": scenario["name"],
                                   "mutated_account": item["account"],
                                   "gaining_accounts": gains,
                                   "candidate_role": item["role_hints"],
                                   "note": "A counterfactual balance change affected payout; reachability, cost, and intended pricing still need review."})
        if scenario["success"] != baseline["success"]:
            hypotheses.append({"kind": "account_balance_changes_success",
                               "scenario": scenario["name"],
                               "mutated_account": item["account"],
                               "note": "A counterfactual balance change changed transaction success; review the failed check."})
    report = {"kind": "role_guided_probe", "source_fixture": str(path),
              "generated_fixture": str(probe_path), "replay_report": str(replay_path),
              "program_id": fixture["program"]["id"],
              "program_sha256": fixture["program"]["sha256"],
              "baseline_success": baseline["success"], "baseline_error": baseline["error"],
              "baseline_token_effects": baseline_effects,
              "token_account_roles": token_accounts,
              "scenarios": scenarios, "hypotheses": hypotheses,
              "limitations": ["A changed outcome is a hypothesis, not proof of a bug or profitable exploit.",
                              "Each scenario changes account bytes directly; a real attacker must be able to reach that state through valid transactions.",
                              "Only selected instruction token accounts are mutated; other account formats and multi-step sequences need separate checks."]}
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "baseline_success": baseline["success"],
            "scenarios": len(scenarios), "hypotheses": len(hypotheses)}



def donation_probe(path: Path, output: Path, runner: Path,
                   basis_points: list[int], max_vaults: int) -> dict:
    """Use a real SPL transfer before replay to test vault-balance influence."""
    fixture = json.loads(path.read_text())
    need(fixture.get("schema_version") == 1, "unsupported replay fixture schema")
    need(fixture["origin"].get("program_version_verified"),
         "donation probe requires a pinned program version")
    need(basis_points and all(0 < value <= 100000 for value in basis_points),
         "donation basis points must be between 1 and 100000")
    need(0 < max_vaults <= 16, "max vaults must be between 1 and 16")
    roles = inspect_fixture(path)["instruction_accounts"]
    token_program = KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"]
    vaults = [item for item in roles if
              "program_vault_candidate" in item["hints"] and
              item["is_writable"] and item["owner"] == token_program]
    workdir = output.parent / (output.stem + "-runs")
    workdir.mkdir(parents=True, exist_ok=True)
    scenarios = []
    for vault in vaults[:max_vaults]:
        pubkey = vault["pubkey"]
        source = fixture["accounts"][pubkey]
        raw = base64.b64decode(source["data_base64"], validate=True)
        if len(raw) < 165 or raw[108] != 1 or raw[109:113] != b"\x00" * 4:
            scenarios.append({"vault": pubkey, "skipped": "unsupported token account state"})
            continue
        amount = struct.unpack_from("<Q", raw, 64)[0]
        for bps in sorted(set(basis_points)):
            donation = max(1, amount * bps // 10000)
            if donation > (1 << 64) - 2:
                scenarios.append({"vault": pubkey, "basis_points": bps,
                                  "skipped": "donation exceeds u64"})
                continue
            donor = b58encode(hashlib.sha256(
                (fixture["program"]["id"] + pubkey + str(bps) + "donation").encode()
            ).digest())
            need(donor not in fixture["accounts"], "synthetic donor address collision")
            pair = []
            for variant in ("control", "donation"):
                copy = json.loads(path.read_text())
                copy["mutations"] = []
                donor_account = dict(source)
                donor_data = bytearray(raw)
                donor_data[32:64] = b58decode(copy["payer"])
                struct.pack_into("<Q", donor_data, 64, donation + 1)
                donor_data[72:76] = b"\x00" * 4
                donor_data[121:129] = b"\x00" * 8
                donor_account["data_base64"] = base64.b64encode(donor_data).decode()
                copy["accounts"][donor] = donor_account
                if variant == "donation":
                    transfer = {"program_id": token_program,
                                "accounts": [
                                    {"pubkey": donor, "is_signer": False, "is_writable": True},
                                    {"pubkey": pubkey, "is_signer": False, "is_writable": True},
                                    {"pubkey": copy["payer"], "is_signer": True,
                                     "is_writable": False}],
                                "data_base64": base64.b64encode(
                                    bytes([3]) + struct.pack("<Q", donation)).decode()}
                    copy["prelude_instructions"] = (copy.get("prelude_instructions", []) +
                                                    [transfer])
                case_path = workdir / f"{vault['index']}-{bps}-{variant}.json"
                replay_path = workdir / f"{vault['index']}-{bps}-{variant}-replay.json"
                for program in [copy["program"]] + copy.get("extra_programs", []):
                    program["elf"] = os.path.relpath(
                        (path.parent / program["elf"]).resolve(), case_path.parent.resolve())
                case_path.write_text(json.dumps(copy, indent=2) + "\n")
                replay_fixture(case_path, replay_path, runner)
                pair.append(json.loads(replay_path.read_text())["scenarios"][0])
            control, changed = pair
            step = changed["steps"][-1] if changed["steps"] else None
            transfer_succeeded = (len(changed["steps"]) >= 2 and
                                  changed["steps"][-2]["program_id"] == token_program and
                                  changed["steps"][-2]["success"])
            token_effects = []
            keys = set(control["changes"]) | set(changed["changes"])
            for key in sorted(keys - {donor, pubkey}):
                baseline_change = control["changes"].get(key)
                donation_change = changed["changes"].get(key)
                baseline_delta = (baseline_change or {}).get("effect", {}).get(
                    "spl_token_amount_delta")
                donation_delta = (donation_change or {}).get("effect", {}).get(
                    "spl_token_amount_delta")
                if baseline_delta is not None and donation_delta is not None and baseline_delta != donation_delta:
                    token_effects.append({"account": key,
                                          "control_delta": baseline_delta,
                                          "donation_delta": donation_delta,
                                          "difference": donation_delta - baseline_delta})
            scenarios.append({"vault": pubkey, "vault_account_index": vault["index"],
                              "basis_points": bps, "donation_amount": donation,
                              "donor": donor, "donor_funding_assumption": donation + 1,
                              "control_success": control["success"],
                              "transfer_succeeded": transfer_succeeded,
                              "target_success": bool(step and step["success"]),
                              "token_effect_changes": token_effects,
                              "balance_sensitive_candidate": bool(
                                  control["success"] and transfer_succeeded and
                                  step and step["success"] and token_effects)})
    found = [row for row in scenarios if row.get("balance_sensitive_candidate")]
    report = {"kind": "valid_transfer_balance_probe", "fixture": str(path),
              "program_id": fixture["program"]["id"],
              "program_sha256": fixture["program"]["sha256"],
              "candidate_found": bool(found), "scenarios": scenarios,
              "limitations": ["The donor token account is synthetic; obtaining its stated token balance may be costly or impossible for a real attacker.",
                              "LiteSVM skips signature verification while retaining signer flags.",
                              "A changed output after a valid transfer is balance sensitivity, not proof of a profitable or unintended exploit.",
                              "Only classic SPL Token initialized vaults with a program-owned authority are probed."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "vaults": len(vaults),
            "scenarios": len(scenarios), "candidates": len(found)}


def run_blind_benchmark(manifest_path: Path, output: Path, runner: Path) -> dict:
    """Run detection without loading the separate expected-label file."""
    manifest = json.loads(manifest_path.read_text())
    need(manifest.get("schema_version") == 1 and manifest.get("cases"),
         "blind benchmark manifest needs schema_version 1 and cases")
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for case in manifest["cases"]:
        name = case["name"]
        need(re.fullmatch(r"[a-z0-9-]+", name) is not None,
             f"invalid blind benchmark case name {name}")
        fixture_path = (manifest_path.parent / case["fixture"]).resolve()
        fixture = json.loads(fixture_path.read_text())
        need(fixture["program"]["sha256"] == case["program_sha256"],
             f"blind benchmark ELF pin mismatch for {name}")
        path = output / name / "donation.json"
        result = donation_probe(fixture_path, path, runner,
                                case.get("basis_points", [1000]),
                                case.get("max_vaults", 4))
        report = json.loads(Path(result["report"]).read_text())
        rows.append({"name": name, "program_sha256": case["program_sha256"],
                     "candidate_found": report["candidate_found"],
                     "scenarios": result["scenarios"], "report": str(path)})
    predictions = {"kind": "blind_program_predictions", "manifest": str(manifest_path),
                   "cases": rows,
                   "note": "No expected labels or source-level account offsets were read by the detector."}
    path = output / "predictions.json"
    path.write_text(json.dumps(predictions, indent=2) + "\n")
    return {"predictions": str(path), "cases": len(rows),
            "candidates": sum(row["candidate_found"] for row in rows)}


def score_blind_benchmark(predictions_path: Path, labels_path: Path,
                          output: Path) -> dict:
    predictions = json.loads(predictions_path.read_text())
    labels = json.loads(labels_path.read_text())
    need(predictions.get("kind") == "blind_program_predictions", "invalid predictions")
    need(labels.get("schema_version") == 1, "invalid benchmark labels")
    expected = {item["name"]: item for item in labels["cases"]}
    rows = []
    for item in predictions["cases"]:
        label = expected.get(item["name"])
        if label is None:
            rows.append({**item, "label_status": "unlabeled"})
            continue
        need(label["program_sha256"] == item["program_sha256"],
             f"benchmark label ELF pin mismatch for {item['name']}")
        prediction = item["candidate_found"]
        truth = label["known_balance_donation_bug"]
        rows.append({**item, "known_balance_donation_bug": truth,
                     "label_status": "scored", "correct": prediction == truth,
                     "evidence": label["evidence"],
                     "control_kind": label.get("control_kind")})
    scored = [item for item in rows if item["label_status"] == "scored"]
    comparable = [item for item in scored if item.get("control_kind") != "unrelated_program"]
    unrelated = [item for item in scored if item.get("control_kind") == "unrelated_program"]
    matrix = {"true_positive": sum(r["candidate_found"] and r["known_balance_donation_bug"] for r in comparable),
              "false_positive": sum(r["candidate_found"] and not r["known_balance_donation_bug"] for r in comparable),
              "true_negative": sum(not r["candidate_found"] and not r["known_balance_donation_bug"] for r in comparable),
              "false_negative": sum(not r["candidate_found"] and r["known_balance_donation_bug"] for r in comparable)}
    fixed_controls = sum(r.get("control_kind") == "verified_fixed_version" for r in comparable)
    report = {"kind": "blind_benchmark_score", "predictions": str(predictions_path),
              "labels": str(labels_path), "cases": rows, "comparable_confusion": matrix,
              "unrelated_controls": len(unrelated),
              "deployed_known_bug_positives": sum(r["known_balance_donation_bug"] for r in comparable),
              "verified_fixed_version_controls": fixed_controls,
              "field_accuracy_measurable": fixed_controls > 0 and matrix["true_positive"] + matrix["false_negative"] > 1,
              "limitations": ["The detector tests whether a valid unsolicited SPL Token transfer changes later token effects; it does not decide whether the behavior is an exploitable bug.",
                              "The positive was publicly disclosed before this detector was built, so this is a held-out label run, not a prospective discovery.",
                              "The published fixed GoonFi version can remain balance-sensitive; a positive signal on it is a false positive as a bug verdict.",
                              "Unrelated programs without a vault path are excluded from specificity calculations.",
                              "One vulnerable/fixed pair cannot estimate accuracy across deployed programs."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output), "scored_cases": len(scored),
            "comparable_confusion": matrix, "fixed_controls": fixed_controls}


def run_bug_checks(spec_path: Path, output: Path, runner: Path) -> dict:
    """Run declared security invariants against controlled local transactions."""
    spec = json.loads(spec_path.read_text())
    need(spec.get("schema_version") == 1 and isinstance(spec.get("checks"), list),
         "bug-check spec needs schema_version 1 and checks")
    fixture_path = (spec_path.parent / spec["fixture"]).resolve()
    source = json.loads(fixture_path.read_text())
    need(source["origin"].get("program_version_verified"),
         "security checks require a verified pinned program version")
    output.mkdir(parents=True, exist_ok=True)
    results = []

    def token_amount(account: str, scenario: dict) -> int:
        change = scenario["changes"].get(account)
        if change:
            after = change["after"]
            need(after is not None and after["spl_token_amount"] is not None,
                 f"{account} is not an SPL token account after replay")
            return after["spl_token_amount"]
        record = source["accounts"].get(account)
        need(record is not None, f"missing token account {account}")
        data = base64.b64decode(record["data_base64"], validate=True)
        need(len(data) >= 72, f"token account {account} is too short")
        return struct.unpack_from("<Q", data, 64)[0]

    def field_value(field: dict, mutation: dict) -> int:
        record = source["accounts"].get(field["account"])
        need(record is not None, f"missing field account {field['account']}")
        data = bytearray(base64.b64decode(record["data_base64"], validate=True))
        if mutation.get("account") == field["account"] and mutation.get("data_base64"):
            replacement = base64.b64decode(mutation["data_base64"], validate=True)
            offset = mutation.get("offset", 0)
            need(0 <= offset <= len(data) - len(replacement), "field mutation out of bounds")
            data[offset:offset + len(replacement)] = replacement
        fmt = {"u64_le": "<Q", "i64_le": "<q"}.get(field.get("encoding", "u64_le"))
        need(fmt is not None and 0 <= field["offset"] <= len(data) - 8,
             "invalid field encoding or offset")
        return struct.unpack_from(fmt, data, field["offset"])[0]

    def replayed_field(field: dict, scenario: dict) -> int:
        change = scenario["changes"].get(field["account"])
        if not change:
            return field_value(field, {})
        after = change["after"]
        need(after is not None and after.get("data_base64") is not None,
             f"replay did not include bytes for {field['account']}")
        data = base64.b64decode(after["data_base64"], validate=True)
        fmt = {"u64_le": "<Q", "i64_le": "<q"}.get(field.get("encoding", "u64_le"))
        need(fmt is not None and 0 <= field["offset"] <= len(data) - 8,
             "invalid replayed field offset")
        return struct.unpack_from(fmt, data, field["offset"])[0]

    for check in spec["checks"]:
        name, kind = check["name"], check["kind"]
        need(re.fullmatch(r"[a-z0-9-]+", name) is not None and kind in {
            "authorization", "replay_protection", "stale_oracle", "slippage",
            "lending_solvency"},
            f"invalid check {name} or kind {kind}")
        folder = output / name
        folder.mkdir(parents=True, exist_ok=True)
        fixture = json.loads(fixture_path.read_text())
        if "instruction_data_base64" in check:
            fixture["instruction"]["data_base64"] = check["instruction_data_base64"]
        fixture["prelude_instructions"] = check.get("prelude_instructions", [])
        mutation = dict(check.get("mutation") or {})
        if mutation:
            mutation.setdefault("name", name)
            mutation.setdefault("account", "")
        fixture["mutations"] = [mutation] if mutation else []
        for program in [fixture["program"]] + fixture.get("extra_programs", []):
            program["elf"] = os.path.relpath(
                (fixture_path.parent / program["elf"]).resolve(), folder.resolve())
        case_path, replay_path = folder / "fixture.json", folder / "replay.json"
        case_path.write_text(json.dumps(fixture, indent=2) + "\n")
        replay_fixture(case_path, replay_path, runner, include_account_data=True)
        replay = json.loads(replay_path.read_text())
        baseline = replay["scenarios"][0]
        need(baseline["success"],
             f"security check {name} baseline failed: {baseline['error']}")
        scenario = replay["scenarios"][-1]
        observation = {}
        finding = False
        if kind == "authorization":
            overrides = mutation.get("signer_overrides") or {}
            need(overrides and all(value is False for value in overrides.values()),
                 "authorization check must remove at least one signer")
            originals = {item["pubkey"]: item["is_signer"]
                         for item in source["instruction"]["accounts"]}
            need(all(originals.get(pubkey) for pubkey in overrides),
                 "authorization check must remove an original instruction signer")
            need(source["payer"] not in overrides,
                 "cannot remove the fee payer signer; use an independent payer fixture")
            finding = baseline["success"] and scenario["success"]
            observation = {"removed_signers": sorted(overrides),
                           "baseline_success": baseline["success"],
                           "unsigned_success": scenario["success"]}
        elif kind == "replay_protection":
            prior = fixture["prelude_instructions"]
            replayed_data = mutation.get("instruction_data_base64")
            need(prior and replayed_data and
                 prior[-1]["data_base64"] == replayed_data and
                 prior[-1]["program_id"] == fixture["instruction"]["program_id"] and
                 prior[-1]["accounts"] == fixture["instruction"]["accounts"] and
                 fixture["instruction"]["data_base64"] != replayed_data,
                 "replay protection check must repeat a prior instruction after a distinct baseline")
            need(len(scenario["steps"]) == len(prior) + 1 and
                 all(step["success"] for step in scenario["steps"][:-1]),
                 "replay protection prelude must succeed")
            finding = baseline["success"] and scenario["success"]
            observation = {"prior_instruction_reused": True,
                           "baseline_success": baseline["success"],
                           "replayed_instruction_success": scenario["success"]}
        elif kind == "stale_oracle":
            oracle_time = field_value(check["oracle_timestamp"], mutation)
            clock_bytes = source["origin"].get("clock_sysvar_base64")
            need(clock_bytes is not None, "stale oracle check needs archived Clock")
            clock_time = mutation.get("clock_unix_timestamp",
                struct.unpack_from("<q", base64.b64decode(clock_bytes), 32)[0])
            age = clock_time - oracle_time
            need(age > check["max_age_seconds"] >= 0,
                 "stale oracle input does not exceed configured maximum age")
            finding = baseline["success"] and scenario["success"]
            observation = {"oracle_age_seconds": age,
                           "max_age_seconds": check["max_age_seconds"],
                           "stale_input_accepted": scenario["success"]}
        elif kind == "slippage":
            min_out = check["minimum_output_amount"]
            encoded_instruction = (mutation.get("instruction_data_base64") or
                                   fixture["instruction"]["data_base64"])
            instruction_bytes = base64.b64decode(encoded_instruction, validate=True)
            min_offset = check["minimum_output_instruction_offset"]
            need(0 <= min_offset <= len(instruction_bytes) - 8 and
                 struct.unpack_from("<Q", instruction_bytes, min_offset)[0] == min_out,
                 "minimum output does not match the mutated instruction bytes")
            if "output_field" in check:
                source_amount = field_value(check["output_field"], {})
                baseline_out = replayed_field(check["output_field"], baseline) - source_amount
                actual_out = replayed_field(check["output_field"], scenario) - source_amount
            else:
                account = check["output_token_account"]
                source_amount = token_amount(account, {"changes": {}})
                baseline_out = token_amount(account, baseline) - source_amount
                actual_out = token_amount(account, scenario) - source_amount
            need(min_out > 0, "minimum output must be positive")
            finding = scenario["success"] and actual_out < min_out
            observation = {"minimum_output_amount": min_out,
                           "actual_output_amount": actual_out,
                           "baseline_output_amount": baseline_out,
                           "below_minimum_accepted": finding}
        else:
            collateral_amount = (replayed_field(check["collateral_field"], scenario)
                                 if "collateral_field" in check else
                                 token_amount(check["collateral_token_account"], scenario))
            debt_amount = (replayed_field(check["debt_field"], scenario)
                           if "debt_field" in check else
                           token_amount(check["debt_token_account"], scenario))
            cp, dp = check["collateral_price"], check["debt_price"]
            max_ltv = check["max_ltv_bps"]
            collateral_decimals = check.get("collateral_decimals", 0)
            debt_decimals = check.get("debt_decimals", 0)
            need(cp > 0 and dp > 0 and 0 <= max_ltv <= 10000,
                 "invalid lending prices or loan-to-value limit")
            need(0 <= collateral_decimals <= 18 and 0 <= debt_decimals <= 18,
                 "lending token decimals must be between 0 and 18")
            collateral_value = collateral_amount * cp * 10**debt_decimals
            debt_value = debt_amount * dp * 10**collateral_decimals
            baseline_collateral = (replayed_field(check["collateral_field"], baseline)
                if "collateral_field" in check else
                token_amount(check["collateral_token_account"], baseline))
            baseline_debt = (replayed_field(check["debt_field"], baseline)
                if "debt_field" in check else
                token_amount(check["debt_token_account"], baseline))
            baseline_solvent = (baseline_debt * dp * 10**collateral_decimals * 10000 <=
                                baseline_collateral * cp * 10**debt_decimals * max_ltv)
            finding = (baseline["success"] and baseline_solvent and scenario["success"]
                       and debt_amount > baseline_debt and
                       debt_value * 10000 > collateral_value * max_ltv)
            observation = {"collateral_value": collateral_value, "debt_value": debt_value,
                           "max_ltv_bps": max_ltv, "baseline_solvent": baseline_solvent,
                           "insolvent_state_accepted": finding}
        row = {"name": name, "kind": kind, "finding": finding,
               "baseline_success": baseline["success"],
               "scenario_success": scenario["success"],
               "scenario_error": scenario["error"], "steps": scenario["steps"],
               "observation": observation, "replay": str(replay_path),
               "evidence_level": "local_counterfactual"}
        if "expected_finding" in check:
            row["expected_finding"] = check["expected_finding"]
            row["classification_correct"] = finding == check["expected_finding"]
        for assertion in check.get("state_assertions", []):
            field = assertion["field"]
            baseline_value = replayed_field(field, baseline)
            scenario_value = replayed_field(field, scenario)
            expected_baseline = assertion["baseline"]
            expected_scenario = assertion["scenario"]
            matched = (baseline_value == expected_baseline and
                       scenario_value == expected_scenario)
            row.setdefault("state_assertions", []).append({
                "field": field, "baseline": baseline_value,
                "scenario": scenario_value,
                "expected_baseline": expected_baseline,
                "expected_scenario": expected_scenario,
                "matched": matched})
            row["classification_correct"] = (
                row.get("classification_correct", True) and matched)
        if "expected_error_contains" in check:
            row["expected_error_contains"] = check["expected_error_contains"]
            row["expected_error_matched"] = (
                check["expected_error_contains"] in (scenario["error"] or ""))
            row["classification_correct"] = (row.get("classification_correct", True)
                                             and row["expected_error_matched"])
        results.append(row)
    labeled = [row for row in results if "expected_finding" in row]
    confusion = {key: sum(row["finding"] == predicted and
                          row["expected_finding"] == actual for row in labeled)
                 for key, predicted, actual in (("true_positive", True, True),
                                               ("false_positive", True, False),
                                               ("true_negative", False, False),
                                               ("false_negative", False, True))}
    report = {"kind": "security_checks", "source_fixture": str(fixture_path),
              "evidence_class": spec.get("evidence_class", "unclassified"),
              "checks": results, "confusion": confusion,
              "limitations": ["A local counterfactual is not proof that an attacker can create the input or profit from it.",
                              "Field offsets, price units, and intended policy must be declared and reviewed for each program.",
                              "Multi-transaction preludes execute in one LiteSVM instance but do not recreate unprovided chain history."]}
    output_path = output / "summary.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output_path), "checks": len(results), "confusion": confusion}


def run_benchmark(manifest_path: Path, output: Path, runner: Path,
                  ghidra: Path | None) -> dict:
    """Run pinned static and execution cases from unrelated Solana programs."""
    manifest = json.loads(manifest_path.read_text())
    need(manifest.get("schema_version") == 1 and manifest.get("cases"),
         "benchmark manifest needs schema_version 1 and cases")
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for case in manifest["cases"]:
        name = case["name"]
        need(re.fullmatch(r"[a-z0-9-]+", name) is not None,
             f"invalid benchmark case name {name}")
        directory = output / name
        directory.mkdir(parents=True, exist_ok=True)
        elf_path = (manifest_path.parent / case["elf"]).resolve()
        actual_hash = hashlib.sha256(elf_path.read_bytes()).hexdigest()
        checks = {"pinned_elf": actual_hash == case["sha256"]}
        row = {"name": name, "program_sha256": actual_hash, "checks": checks}
        if checks["pinned_elf"]:
            analysis = analyze(elf_path, directory / "analysis")
            row["instruction_count"] = analysis["instruction_count"]
            row["function_count"] = analysis["function_count"]
            checks["function_coverage"] = (analysis["function_count"] >=
                                            case.get("minimum_functions", 0))
            if ghidra is not None:
                decompiled = decompile(elf_path, directory / "ghidra", ghidra,
                                       None, None, False)
                row["ghidra"] = decompiled
                checks["ghidra_completed"] = bool(decompiled)
            if case.get("fixture"):
                fixture_path = (manifest_path.parent / case["fixture"]).resolve()
                fixture = json.loads(fixture_path.read_text())
                checks["fixture_pins_elf"] = fixture["program"]["sha256"] == actual_hash
                if checks["fixture_pins_elf"]:
                    report_path = directory / "replay.json"
                    replay_fixture(fixture_path, report_path, runner)
                    replay = json.loads(report_path.read_text())
                    baseline = replay["scenarios"][0]
                    row["baseline"] = {"success": baseline["success"],
                                       "error": baseline["error"],
                                       "compute_units": baseline["compute_units"]}
                    if "expected_baseline_success" in case:
                        checks["baseline_success"] = (baseline["success"] ==
                                                      case["expected_baseline_success"])
                    if "expected_compute_units" in case:
                        checks["compute_units"] = (baseline["compute_units"] ==
                                                   case["expected_compute_units"])
                    if "expected_token_delta" in case:
                        expected = case["expected_token_delta"]
                        change = baseline["changes"].get(expected["account"])
                        checks["token_delta"] = bool(change and
                            change["effect"]["spl_token_amount_delta"] == expected["delta"])
                    for expected in case.get("expected_mutations", []):
                        name = expected["name"]
                        matches = [item for item in replay["scenarios"][1:]
                                   if item["name"] == name]
                        checks[f"mutation_{name}_present"] = len(matches) == 1
                        if len(matches) != 1:
                            continue
                        scenario = matches[0]
                        if "success" in expected:
                            checks[f"mutation_{name}_success"] = (
                                scenario["success"] == expected["success"])
                        if "compute_units" in expected:
                            checks[f"mutation_{name}_compute_units"] = (
                                scenario["compute_units"] == expected["compute_units"])
                        if "token_delta" in expected:
                            token = expected["token_delta"]
                            change = scenario["changes"].get(token["account"])
                            checks[f"mutation_{name}_token_delta"] = bool(change and
                                change["effect"]["spl_token_amount_delta"] == token["delta"])
        row["passed"] = all(checks.values())
        results.append(row)
    security_runs = []
    total_confusion = {key: 0 for key in ("true_positive", "false_positive",
                                           "true_negative", "false_negative")}
    for item in manifest.get("security_check_specs", []):
        spec_path = (manifest_path.parent / item).resolve()
        name = spec_path.stem
        result = run_bug_checks(spec_path, output / "security" / name, runner)
        run = json.loads(Path(result["report"]).read_text())
        security_runs.append({"name": name, "spec": str(spec_path),
                              "evidence_class": run["evidence_class"],
                              "checks": len(run["checks"]),
                              "passed": all(row.get("classification_correct", False)
                                            for row in run["checks"]),
                              "confusion": run["confusion"]})
        for key, value in run["confusion"].items():
            total_confusion[key] += value
    tp, fp = total_confusion["true_positive"], total_confusion["false_positive"]
    fn = total_confusion["false_negative"]
    security_summary = {"runs": security_runs,
                        "passed": all(row["passed"] for row in security_runs),
                        "confusion": total_confusion,
                        "precision": tp / (tp + fp) if tp + fp else None,
                        "recall": tp / (tp + fn) if tp + fn else None,
                        "real_world_known_bug_cases": sum(
                            row["checks"] for row in security_runs
                            if row["evidence_class"] == "real_world_known_bug"),
                        "independent_example_known_bug_cases": sum(
                            row["checks"] for row in security_runs
                            if row["evidence_class"] == "independent_example_known_bug"),
                        "independent_example_clean_control_cases": sum(
                            row["checks"] for row in security_runs
                            if row["evidence_class"] == "independent_example_clean_control")}
    summary = {"kind": "soldecomp_benchmark", "manifest": str(manifest_path),
               "cases": results, "passed": (all(item["passed"] for item in results)
                                           and security_summary["passed"]),
               "passed_cases": sum(item["passed"] for item in results),
               "total_cases": len(results), "security_benchmark": security_summary}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


CRATE_PATH = re.compile(r"(?:registry/src/[^/]+/|^|[^a-z0-9])"
                        r"([a-z][a-z0-9_-]*?)-(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)/")


def rodata_text(elf: ELF) -> str:
    """Full decoded text of allocated read-only data, without string truncation."""
    parts = []
    for section in elf.sections:
        if section.kind == 1 and section.flags & 2 and not section.flags & 4 and section.size:
            parts.append(elf.section_data(section).decode("latin-1"))
    return "\n".join(parts)


def fingerprint_binary(elf: ELF) -> dict:
    """Recover crate versions and toolchain hints from embedded build paths."""
    blob = rodata_text(elf)
    symbol_names = " ".join(symbol.name for symbol in elf.symbols if symbol.name)
    crates = {}
    for name, version in CRATE_PATH.findall(blob):
        crates.setdefault(name.replace("_", "-"), version)
    toolchain = "solana-platform-tools" if "platform-tools/out/rust/library" in blob else None
    rustc = re.search(r"rustc/([0-9a-f]{7,40})/library", blob)
    anchor = crates.get("anchor-lang")
    return {"crates": [{"name": name, "version": version}
                       for name, version in sorted(crates.items())],
            "toolchain": toolchain, "rustc_commit": rustc.group(1) if rustc else None,
            "anchor_version": anchor,
            "has_anchor_symbols": "anchor_lang" in symbol_names,
            "has_pinocchio": "pinocchio" in blob or "pinocchio" in symbol_names}


def detect_framework(elf_path: Path, idl_path: Path | None) -> dict:
    """Classify a Solana program's framework and recover instruction/account shape."""
    binary = elf_path.read_bytes()
    elf = ELF(binary)
    code = instructions(elf)
    fingerprint = fingerprint_binary(elf)
    blob = rodata_text(elf)
    signals = []
    if fingerprint["anchor_version"]:
        signals.append(f"anchor-lang {fingerprint['anchor_version']} in build paths")
    if fingerprint["has_anchor_symbols"]:
        signals.append("anchor_lang symbols present")
    if "AnchorError occurred" in blob or "AccountDiscriminatorMismatch" in blob:
        signals.append("Anchor runtime error strings present")
    if fingerprint["has_pinocchio"]:
        signals.append("pinocchio present")
    anchor = bool(fingerprint["anchor_version"] or fingerprint["has_anchor_symbols"]
                  or "AnchorError occurred" in blob)
    if anchor:
        framework = "anchor"
    elif fingerprint["has_pinocchio"]:
        framework = "pinocchio"
    elif any(crate["name"].startswith("solana-") for crate in fingerprint["crates"]):
        framework = "native"
        signals.append("solana-* crates without a framework marker")
    else:
        framework = "unknown"

    def discriminator(name: str) -> str:
        snake = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()
        return hashlib.sha256(f"global:{snake}".encode()).digest()[:8].hex()

    recovered = []
    for match in sorted(set(re.findall(r"Instruction: ([A-Za-z][A-Za-z0-9]*)", blob))):
        recovered.append({"name": match, "source": "log_string",
                          "anchor_discriminator_guess": discriminator(match)})
    idl = None
    if idl_path is not None:
        document = json.loads(idl_path.read_text())
        idl = {"address": document.get("address") or document.get("metadata", {}).get("address"),
               "name": document.get("name") or document.get("metadata", {}).get("name"),
               "instructions": []}
        for item in document.get("instructions", []):
            disc = item.get("discriminator")
            idl["instructions"].append({"name": item.get("name"),
                "discriminator": (bytes(disc).hex() if isinstance(disc, list)
                                  else discriminator(item.get("name", ""))),
                "accounts": [{"name": account.get("name"),
                              "writable": account.get("writable", account.get("isMut", False)),
                              "signer": account.get("signer", account.get("isSigner", False))}
                             for account in item.get("accounts", [])]})
    return {"input": str(elf_path.resolve()), "sha256": hashlib.sha256(binary).hexdigest(),
            "framework": framework, "signals": signals,
            "sbpf": sbpf_version(elf.e_flags),
            "fingerprint": fingerprint,
            "hashed_syscalls": sorted(set(hashed_syscalls(elf, code).values())),
            "instructions_from_binary": recovered, "idl": idl,
            "limitations": ["Framework and versions are inferred from embedded strings and symbols; a fully stripped release can hide them.",
                            "Anchor discriminator guesses assume the log name maps to a snake_case method; confirm against an IDL or a live instruction.",
                            "An IDL supplied here is trusted as given and is not verified against the on-chain program."]}


GENERIC_DETECTORS = ("missing_signer", "missing_owner", "account_substitution",
                     "arbitrary_cpi", "balance_sensitivity")


def scan_program(fixture_path: Path, output: Path, runner: Path,
                 max_accounts: int) -> dict:
    """Run framework-agnostic bug detectors derived from the fixture itself."""
    source = json.loads(fixture_path.read_text())
    need(source.get("schema_version") == 1, "unsupported replay fixture schema")
    need(source["origin"].get("program_version_verified"),
         "scan requires a verified pinned program version")
    output.mkdir(parents=True, exist_ok=True)
    roles = inspect_fixture(fixture_path)["instruction_accounts"]
    payer = source["payer"]
    program_id = source["program"]["id"]
    system = KNOWN_PROGRAM_IDS["SOLANA_SYSTEM_PROGRAM_ID"]
    token = KNOWN_PROGRAM_IDS["SOLANA_TOKEN_PROGRAM_ID"]
    program_ids = set(KNOWN_PROGRAM_IDS.values())
    invoked_program = source["instruction"]["program_id"]
    # Signer and program-id substitution rewrite the instruction meta, which the
    # runner only allows for an isolated instruction, not a full transaction.
    isolated = source["origin"].get("replay_mode") != "full_transaction"
    signer_mutations, owner_mutations, discriminator_mutations = [], [], []
    cpi_mutations = []
    seen = set()
    for item in roles if isolated else []:
        pubkey = item["pubkey"]
        if item["is_signer"] and pubkey != payer and pubkey not in seen:
            seen.add(pubkey)
            signer_mutations.append({"name": f"unsigned-{item['index']}", "account": "",
                                     "signer_overrides": {pubkey: False}, "_target": pubkey})
    for item in roles[:max_accounts]:
        pubkey, owner = item["pubkey"], item["owner"]
        # Read-only accounts avoid the runtime's own write-ownership guard, so a
        # surviving owner swap isolates a missing program-level owner check.
        # Signers are skipped: their authority is the signature, not the owner,
        # so a surviving owner swap on a signer is expected, not a finding.
        if (owner is None or item["is_writable"] or item["is_signer"]
                or pubkey == payer or pubkey in program_ids
                or "instructions_sysvar" in item["hints"]):
            continue
        sentinel = system if owner != system else token
        owner_mutations.append({"name": f"wrong-owner-{item['index']}", "account": pubkey,
                                "owner": sentinel, "_target": pubkey, "_from": owner})
    for item in roles[:max_accounts]:
        pubkey = item["pubkey"]
        # Anchor and tagged native state carry an 8-byte type discriminator at
        # the start of a program-owned account. Flipping it probes whether the
        # program validates the account type before using it.
        if item["owner"] != program_id or item["is_signer"]:
            continue
        snapshot = source["accounts"].get(pubkey)
        if snapshot is None:
            continue
        data = base64.b64decode(snapshot["data_base64"], validate=True)
        if len(data) < 8:
            continue
        flipped = bytes(byte ^ 0xFF for byte in data[:8])
        discriminator_mutations.append(
            {"name": f"wrong-discriminator-{item['index']}", "account": pubkey, "offset": 0,
             "data_base64": base64.b64encode(flipped).decode(), "_target": pubkey})
    for item in roles if isolated else []:
        pubkey = item["pubkey"]
        snapshot = source["accounts"].get(pubkey)
        # A program the instruction carries as an account is a likely CPI
        # target. Substituting its id probes whether the callee pins the
        # expected program before invoking it (arbitrary CPI).
        is_program = (pubkey in program_ids
                      or (snapshot is not None and snapshot.get("executable")))
        if not is_program or item["is_signer"] or pubkey == invoked_program:
            continue
        sentinel = system if pubkey != system else token
        cpi_mutations.append({"name": f"swap-program-{item['index']}", "account": "",
                              "instruction_account_override": {pubkey: sentinel},
                              "_target": pubkey, "_to": sentinel})
    working = json.loads(fixture_path.read_text())
    for program in [working["program"]] + working.get("extra_programs", []):
        program["elf"] = os.path.relpath(
            (fixture_path.parent / program["elf"]).resolve(), output.resolve())
    working["mutations"] = [{k: v for k, v in m.items() if not k.startswith("_")}
                            for m in signer_mutations + owner_mutations
                            + discriminator_mutations + cpi_mutations]
    scan_fixture = output / "scan-fixture.json"
    scan_replay = output / "scan-replay.json"
    scan_fixture.write_text(json.dumps(working, indent=2) + "\n")
    replay_fixture(scan_fixture, scan_replay, runner)
    replay = json.loads(scan_replay.read_text())
    baseline = replay["scenarios"][0]
    by_name = {scenario["name"]: scenario for scenario in replay["scenarios"][1:]}
    findings = []
    detectors = {name: {"ran": False, "finding": False, "observations": []}
                 for name in GENERIC_DETECTORS}
    for mutation in signer_mutations:
        detectors["missing_signer"]["ran"] = True
        scenario = by_name[mutation["name"]]
        hit = bool(baseline["success"] and scenario["success"])
        detectors["missing_signer"]["observations"].append(
            {"account": mutation["_target"], "unsigned_success": scenario["success"]})
        if hit:
            detectors["missing_signer"]["finding"] = True
            findings.append({"detector": "missing_signer", "account": mutation["_target"],
                             "note": "Instruction succeeded after a required signer was removed; confirm the account must authorize this action."})
    for mutation in owner_mutations:
        detectors["missing_owner"]["ran"] = True
        scenario = by_name[mutation["name"]]
        hit = bool(baseline["success"] and scenario["success"])
        detectors["missing_owner"]["observations"].append(
            {"account": mutation["_target"], "swapped_from": mutation["_from"],
             "swapped_to": mutation["owner"], "wrong_owner_success": scenario["success"]})
        if hit:
            detectors["missing_owner"]["finding"] = True
            findings.append({"detector": "missing_owner", "account": mutation["_target"],
                             "note": "Read-only account accepted after its owner was changed to an unrelated program; confirm the program should reject a wrong owner here."})
    for mutation in discriminator_mutations:
        detectors["account_substitution"]["ran"] = True
        scenario = by_name[mutation["name"]]
        hit = bool(baseline["success"] and scenario["success"])
        detectors["account_substitution"]["observations"].append(
            {"account": mutation["_target"], "flipped_discriminator_success": scenario["success"]})
        if hit:
            detectors["account_substitution"]["finding"] = True
            findings.append({"detector": "account_substitution", "account": mutation["_target"],
                             "note": "Program-owned account accepted after its 8-byte type discriminator was changed; confirm the program validates the account type (Anchor discriminator or an equivalent tag)."})
    for mutation in cpi_mutations:
        detectors["arbitrary_cpi"]["ran"] = True
        scenario = by_name[mutation["name"]]
        hit = bool(baseline["success"] and scenario["success"])
        detectors["arbitrary_cpi"]["observations"].append(
            {"account": mutation["_target"], "swapped_to": mutation["_to"],
             "substituted_program_success": scenario["success"]})
        if hit:
            detectors["arbitrary_cpi"]["finding"] = True
            findings.append({"detector": "arbitrary_cpi", "account": mutation["_target"],
                             "note": "Instruction succeeded after a program-id account was replaced with an unrelated program; confirm the program pins the expected program id before any CPI."})
    donation = donation_probe(fixture_path, output / "balance-probe.json", runner,
                              [1000], max_accounts)
    balance_report = json.loads(Path(donation["report"]).read_text())
    detectors["balance_sensitivity"]["ran"] = donation["vaults"] > 0
    detectors["balance_sensitivity"]["finding"] = balance_report["candidate_found"]
    detectors["balance_sensitivity"]["observations"] = [
        {"vault": row["vault"], "balance_sensitive": row.get("balance_sensitive_candidate")}
        for row in balance_report["scenarios"] if "basis_points" in row]
    if balance_report["candidate_found"]:
        findings.append({"detector": "balance_sensitivity",
                         "note": "A valid token transfer into a vault changed program token effects; see the balance probe for reachability caveats."})
    report = {"kind": "generic_scan", "fixture": str(fixture_path),
              "program_id": source["program"]["id"],
              "program_sha256": source["program"]["sha256"],
              "baseline_success": baseline["success"], "baseline_error": baseline["error"],
              "detectors": detectors, "findings": findings,
              "balance_probe": donation["report"],
              "limitations": ["Each detector mutates one input directly; a finding is a hypothesis, not proof that an attacker can reach the state or profit.",
                              "The owner detector only probes read-only accounts, so it misses missing checks on writable accounts the runtime already guards.",
                              "The account-substitution detector flags a program-owned account whose leading 8 bytes are not validated; a program that intentionally uses no type tag is a benign positive, so confirm the account is meant to carry a discriminator.",
                              "The arbitrary-CPI detector replaces a program-id account with an unrelated program and only observes identity pinning; it does not execute a malicious substitute program, so a real CPI target that fails under the substitute is not flagged.",
                              "Absence of a finding is not a safety proof; these detectors do not cover value, arithmetic, or PDA-seed bug classes."]}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return {"report": str(output / "summary.json"), "program_id": source["program"]["id"],
            "findings": [row["detector"] for row in findings],
            "detectors_run": [name for name, info in detectors.items() if info["ran"]]}


def run_corpus_benchmark(manifest_path: Path, output: Path, runner: Path) -> dict:
    """Score the generic detectors against a labeled corpus of pinned programs."""
    manifest = json.loads(manifest_path.read_text())
    need(manifest.get("schema_version") == 1 and manifest.get("cases"),
         "corpus manifest needs schema_version 1 and cases")
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    per_detector = {name: {"true_positive": 0, "false_positive": 0,
                           "true_negative": 0, "false_negative": 0}
                    for name in GENERIC_DETECTORS}
    deployed_scored = 0
    deployed_positive_scored = 0
    for case in manifest["cases"]:
        name = case["name"]
        need(re.fullmatch(r"[a-z0-9-]+", name) is not None,
             f"invalid corpus case name {name}")
        fixture_path = (manifest_path.parent / case["fixture"]).resolve()
        fixture = json.loads(fixture_path.read_text())
        actual = hashlib.sha256((fixture_path.parent / fixture["program"]["elf"])
                                .resolve().read_bytes()).hexdigest()
        need(actual == case["program_sha256"] == fixture["program"]["sha256"],
             f"corpus case {name} pins a different program hash")
        result = scan_program(fixture_path, output / name, runner,
                              case.get("max_accounts", 8))
        report = json.loads(Path(result["report"]).read_text())
        expected = case["expected"]
        # A case may declare expected_prediction when a detector is known to
        # disagree with the true label (e.g. a fixed program that stays balance
        # sensitive). Confusion scores against the true label; the pass gate
        # scores against expected_prediction so documented limits are not reds.
        expected_prediction = case.get("expected_prediction", {})
        scored = {}
        for detector, label in expected.items():
            need(detector in GENERIC_DETECTORS, f"unknown detector {detector}")
            info = report["detectors"][detector]
            need(info["ran"], f"detector {detector} did not run for {name}")
            predicted = info["finding"]
            key = (("true" if predicted == label else "false") +
                   ("_positive" if predicted else "_negative"))
            per_detector[detector][key] += 1
            reference = expected_prediction.get(detector, label)
            scored[detector] = {"expected_label": label, "predicted": predicted,
                                "expected_prediction": reference,
                                "known_limitation": reference != label,
                                "correct": predicted == reference}
        if case.get("deployed"):
            deployed_scored += 1
        if case.get("control_kind") == "deployed_known_bug":
            deployed_positive_scored += 1
        cases.append({"name": name, "control_kind": case.get("control_kind"),
                      "evidence": case.get("evidence"), "deployed": bool(case.get("deployed")),
                      "scored": scored, "all_findings": report["findings"],
                      "report": result["report"]})
    totals = {"true_positive": 0, "false_positive": 0,
              "true_negative": 0, "false_negative": 0}
    for counts in per_detector.values():
        for key, value in counts.items():
            totals[key] += value
    tp, fp, fn = totals["true_positive"], totals["false_positive"], totals["false_negative"]
    without_case = sorted(name for name in GENERIC_DETECTORS
                          if sum(per_detector[name].values()) == 0)
    summary = {"kind": "corpus_benchmark", "manifest": str(manifest_path),
               "cases": cases, "per_detector": per_detector, "confusion": totals,
               "precision": tp / (tp + fp) if tp + fp else None,
               "recall": tp / (tp + fn) if tp + fn else None,
               "passed": all(item["correct"] for case in cases
                             for item in case["scored"].values()),
               "deployed_scored_cases": deployed_scored,
               "deployed_known_bug_cases": deployed_positive_scored,
               "detectors_without_corpus_case": without_case,
               # Recall across real programs needs deployed positives, not just
               # any deployed case, so the gate counts deployed known-bug cases.
               "field_accuracy_measurable": deployed_positive_scored >= 5,
               "limitations": ["This corpus is small and mixes synthetic controls with few deployed cases, so precision and recall do not estimate field accuracy.",
                               "Scoring covers only the five generic detectors; a labeled case asserts a detector verdict, not full program safety.",
                               "A fixed deployed program can still show balance sensitivity, so such a positive is a false positive against a fix label, not a detector defect."]}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("benchmark", help="run pinned cross-program analysis and replay cases")
    p.add_argument("manifest", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p.add_argument("--ghidra", type=Path,
                   help="also run headless Ghidra over each benchmark ELF")
    p = commands.add_parser("fetch", help="download a deployed program ELF")
    p.add_argument("program_id")
    p.add_argument("--rpc", default="https://api.mainnet-beta.solana.com")
    p.add_argument("--out", type=Path, required=True)
    p = commands.add_parser("capture", help="capture a transaction instruction and live account state for replay")
    p.add_argument("signature")
    p.add_argument("--elf", required=True, type=Path, help="pinned ELF for the selected instruction")
    p.add_argument("--instruction-index", type=int, default=0,
                   help="zero-based outer instruction index")
    p.add_argument("--inner-index", type=int,
                   help="zero-based inner CPI instruction index within the outer instruction")
    p.add_argument("--full-transaction", action="store_true",
                   help="capture the original signed transaction and all its accounts")
    p.add_argument("--override-signer", action="append", default=[],
                   help="repeat for a CPI signer omitted from transaction-level flags")
    p.add_argument("--rpc", default="https://api.mainnet-beta.solana.com")
    p.add_argument("--rpc-env", help="environment variable containing the RPC URL")
    p.add_argument("--out", type=Path, required=True)
    p = commands.add_parser("hydrate", help="replace live account bytes with pre-slot archive state")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--slot", type=int, help="archive slot, default transaction slot minus one")
    p.add_argument("--rpc-env", default="SOLDECOMP_ARCHIVE_RPC",
                   help="environment variable containing the archive RPC URL")
    p.add_argument("--provider", default="archive-rpc",
                   help="non-secret provider label saved with the fixture")
    p.add_argument("--features", action="store_true",
                   help="also snapshot runtime feature activation at the transaction slot")
    p = commands.add_parser("mutate", help="append one account or instruction input change to a replay fixture")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--name", required=True)
    p.add_argument("--account", help="account to change, except for instruction bytes")
    change = p.add_mutually_exclusive_group(required=True)
    change.add_argument("--token-amount-delta", type=int,
                        help="change an SPL token account amount relative to its snapshot")
    change.add_argument("--bytes-hex", help="replacement account bytes at --offset")
    change.add_argument("--lamports", type=int, help="replace account lamports")
    change.add_argument("--instruction-hex", help="replace the entire instruction data")
    p.add_argument("--offset", type=int, help="byte offset for --bytes-hex")
    p = commands.add_parser("apply-state", help="copy a checked replayed account into another fixture")
    p.add_argument("fixture", type=Path, help="fixture to update")
    p.add_argument("replay_report", type=Path, help="earlier replay with account data")
    p.add_argument("--account", required=True, help="account to carry forward")
    p.add_argument("--name", default="baseline", help="source replay scenario")
    p.add_argument("--out", required=True, type=Path)
    p = commands.add_parser("archive-simulate", help="run the original full transaction against archived state")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--name", action="append", default=[],
                   help="repeat for up to four account mutations; baseline always runs")
    p.add_argument("--rpc-env", default="SOLDECOMP_ARCHIVE_RPC",
                   help="environment variable containing the archive RPC URL")
    p = commands.add_parser("audit-slot", help="find same-slot writes before the captured transaction")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--rpc-env", default="SOLDECOMP_ARCHIVE_RPC",
                   help="environment variable containing an archive RPC URL")
    p = commands.add_parser("reconstruct-slot", help="replay earlier same-slot writers into a hydrated fixture")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--rpc-env", default="SOLDECOMP_ARCHIVE_RPC")
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("reconcile", help="compare isolated replay with recorded transaction token deltas")
    p.add_argument("fixture", type=Path)
    p.add_argument("replay_report", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--rpc-env", default="SOLDECOMP_ARCHIVE_RPC",
                   help="environment variable containing an RPC URL with transaction history")
    p = commands.add_parser("runtime-audit", help="attribute a historical full-transaction compute gap")
    p.add_argument("fixture", type=Path)
    p.add_argument("comparison", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p = commands.add_parser("replay", help="run a fixture through the local LiteSVM runner")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p.add_argument("--trace-dir", type=Path,
                   help="write LiteSVM register traces to a new directory")
    p.add_argument("--include-account-data", action="store_true",
                   help="include full bytes for changed accounts in the report")
    p = commands.add_parser("trace-exec", help="map LiteSVM register traces to ELF instructions")
    p.add_argument("elf", type=Path)
    p.add_argument("trace_dir", type=Path)
    p.add_argument("--address", action="append", required=True,
                   type=lambda value: int(value, 0))
    p.add_argument("--radius", type=int, default=2)
    p.add_argument("--max-visits", type=int, default=10)
    p.add_argument("--fixture", type=Path,
                   help="label registers equal to token amounts in fixture scenarios")
    p.add_argument("--out", type=Path)
    p = commands.add_parser("trace-roles", help="locate register values controlled by one token amount")
    p.add_argument("fixture", type=Path)
    p.add_argument("--name", required=True, help="existing token amount mutation name")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--flow", type=Path, help="optional Ghidra flow.json for operation labels")
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("discover-fields", help="observe account fields read by a pinned program")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("inspect", help="infer account-role hints from a replay fixture")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", type=Path)
    p = commands.add_parser("probe", help="run role-guided token-balance mutations")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--basis-points", action="append", type=int, default=[],
                   help="repeat for mutation size in basis points; defaults to 100 and 1000")
    p.add_argument("--max-accounts", type=int, default=8)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("probe-donation", help="test whether a valid token transfer changes later program effects")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--basis-points", action="append", type=int, default=[])
    p.add_argument("--max-vaults", type=int, default=4)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("blind-benchmark", help="run sealed donation predictions without loading labels")
    p.add_argument("manifest", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("score-blind", help="score pinned blind predictions against separate labels")
    p.add_argument("predictions", type=Path)
    p.add_argument("labels", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p = commands.add_parser("bug-checks", help="run configured authorization, oracle, slippage and solvency checks")
    p.add_argument("spec", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("detect-framework", help="classify framework, sBPF version, crates and instruction shape")
    p.add_argument("elf", type=Path)
    p.add_argument("--idl", type=Path, help="optional Anchor IDL JSON to merge account roles")
    p.add_argument("--out", type=Path)
    p = commands.add_parser("scan", help="run framework-agnostic bug detectors over a fixture")
    p.add_argument("fixture", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--max-accounts", type=int, default=8)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("corpus-benchmark", help="score generic detectors against a labeled program corpus")
    p.add_argument("manifest", type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--runner", type=Path, default=Path(__file__).resolve().parent /
                   "replay/target/debug/soldecomp-replay")
    p = commands.add_parser("analyze", help="lift ELF into per-function register code")
    p.add_argument("elf", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p = commands.add_parser("decompile", help="run headless Ghidra to export C-like source")
    p.add_argument("elf", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--ghidra", type=Path, default=Path(__file__).resolve().parent /
                   ".toolchains/ghidra/ghidra_12.1.4_PUBLIC")
    p.add_argument("--function", type=lambda value: int(value, 0))
    p.add_argument("--processor", help="Ghidra language ID, e.g. eBPFSol:LE:64:default")
    p.add_argument("--keep-project", action="store_true",
                   help="retain the corrected Ghidra project for interactive CLI analysis")
    p = commands.add_parser("trace", help="query decompiler call and data-flow evidence")
    p.add_argument("flow", type=Path, help="flow.json from decompile")
    p.add_argument("--function", type=lambda value: int(value, 0))
    p.add_argument("--event", type=lambda value: int(value, 0))
    p.add_argument("--callee", help="exact called function or syscall name")
    p.add_argument("--kind", choices=("call", "callind", "load", "store", "return",
                                      "arithmetic", "branch"))
    p.add_argument("--op", help="arithmetic P-code operation, such as INT_SUB")
    p.add_argument("--parameter", type=int, help="select events fed by this function parameter")
    p.add_argument("--caller", type=lambda value: int(value, 0),
                   help="show only callsites from this function")
    p.add_argument("--via", action="append", type=lambda value: int(value, 0), default=[],
                   help="repeat caller function addresses from callee outward")
    p.add_argument("--no-callers", action="store_true", help="omit caller listings")
    p.add_argument("--limit", type=int, default=25)
    p = commands.add_parser("packet", help="save bounded function evidence for an agent round")
    p.add_argument("flow", type=Path, help="flow.json from decompile")
    p.add_argument("--function", required=True, type=lambda value: int(value, 0))
    p.add_argument("--event", type=lambda value: int(value, 0))
    p.add_argument("--max-events", type=int, default=80)
    p.add_argument("--out", required=True, type=Path)
    p = commands.add_parser("build", help="compile a Rust candidate and optionally score it")
    p.add_argument("project", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--toolchain", type=Path, default=Path(__file__).resolve().parent /
                   ".toolchains/platform-tools-v1.48")
    p.add_argument("--target", type=Path)
    p = commands.add_parser("compare", help="score a candidate program binary")
    p.add_argument("target", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("--map", type=Path)
    p.add_argument("--symbols-from", type=Path, help="unstripped ELF from the same candidate build")
    p.add_argument("--project-crate", action="append", default=[], help="repeat for each local Rust crate")
    p.add_argument("--out", type=Path)
    p = commands.add_parser("judge", help="gate a candidate against a prior build")
    p.add_argument("target", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("--baseline", type=Path)
    p.add_argument("--source", type=Path)
    p.add_argument("--map", type=Path)
    p.add_argument("--baseline-map", type=Path)
    p.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "benchmark":
            result = run_benchmark(args.manifest, args.out, args.runner, args.ghidra)
        elif args.command == "fetch":
            result = fetch(args.program_id, args.rpc, args.out)
        elif args.command == "capture":
            capture_url = os.environ.get(args.rpc_env, "") if args.rpc_env else args.rpc
            need(capture_url.startswith("https://"), "capture RPC URL must use HTTPS")
            result = capture_transaction(args.signature, args.elf,
                                         args.instruction_index, args.inner_index,
                                         args.override_signer, capture_url, args.out,
                                         args.full_transaction)
        elif args.command == "hydrate":
            result = hydrate_fixture(args.fixture, args.out, args.rpc_env,
                                     args.slot, args.provider, args.features)
        elif args.command == "mutate":
            result = mutate_fixture(args.fixture, args.out, args.name, args.account,
                                    args.token_amount_delta, args.offset, args.bytes_hex,
                                    args.lamports, args.instruction_hex)
        elif args.command == "apply-state":
            result = apply_replay_account_state(args.fixture, args.replay_report,
                                                args.account, args.out, args.name)
        elif args.command == "archive-simulate":
            result = archive_simulate_fixture(args.fixture, args.out, args.rpc_env,
                                              args.name)
        elif args.command == "audit-slot":
            result = audit_slot_fixture(args.fixture, args.out, args.rpc_env)
        elif args.command == "reconstruct-slot":
            result = reconstruct_same_slot(args.fixture, args.out, args.rpc_env, args.runner)
        elif args.command == "reconcile":
            result = reconcile_replay(args.fixture, args.replay_report, args.out, args.rpc_env)
        elif args.command == "runtime-audit":
            result = runtime_gap_audit(args.fixture, args.comparison, args.out)
        elif args.command == "replay":
            result = replay_fixture(args.fixture, args.out, args.runner, args.trace_dir,
                                    args.include_account_data)
        elif args.command == "trace-exec":
            result = trace_execution(args.elf, args.trace_dir, args.address,
                                     args.radius, args.max_visits, args.fixture)
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(result, indent=2) + "\n")
                result = {"report": str(args.out), "elf_sha256": result["elf_sha256"],
                          "matched_traces": len(result["traces"]),
                          "visits": [trace["visits"] for trace in result["traces"]]}
        elif args.command == "trace-roles":
            result = trace_roles(args.fixture, args.name, args.out, args.runner, args.flow)
        elif args.command == "discover-fields":
            result = discover_fields(args.fixture, args.out, args.runner)
        elif args.command == "inspect":
            result = inspect_fixture(args.fixture)
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(result, indent=2) + "\n")
                result = {"report": str(args.out),
                          "program_id": result["program_id"],
                          "possible_missing_cpi_signers": result["possible_missing_cpi_signers"],
                          "account_count": len(result["instruction_accounts"])}
        elif args.command == "probe":
            result = probe_fixture(args.fixture, args.out, args.runner,
                                   args.basis_points or [100, 1000], args.max_accounts)
        elif args.command == "probe-donation":
            result = donation_probe(args.fixture, args.out, args.runner,
                                    args.basis_points or [1000], args.max_vaults)
        elif args.command == "blind-benchmark":
            result = run_blind_benchmark(args.manifest, args.out, args.runner)
        elif args.command == "score-blind":
            result = score_blind_benchmark(args.predictions, args.labels, args.out)
        elif args.command == "bug-checks":
            result = run_bug_checks(args.spec, args.out, args.runner)
        elif args.command == "detect-framework":
            result = detect_framework(args.elf, args.idl)
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(json.dumps(result, indent=2) + "\n")
        elif args.command == "scan":
            result = scan_program(args.fixture, args.out, args.runner, args.max_accounts)
        elif args.command == "corpus-benchmark":
            result = run_corpus_benchmark(args.manifest, args.out, args.runner)
        elif args.command == "analyze":
            result = analyze(args.elf, args.out)
            result = {k: v for k, v in result.items()
                      if k not in ("functions", "strings", "leaf_first_work_order")}
        elif args.command == "decompile":
            result = decompile(args.elf, args.out, args.ghidra, args.function,
                               args.processor, args.keep_project)
        elif args.command == "trace":
            result = trace_flow(args.flow, args.function, args.event, args.callee,
                                args.kind, args.op, args.parameter, args.caller,
                                args.via, not args.no_callers, args.limit)
        elif args.command == "packet":
            result = evidence_packet(args.flow, args.function, args.event,
                                     args.max_events, args.out)
        elif args.command == "build":
            result = build_candidate(args.project, args.out, args.toolchain, args.target)
        elif args.command == "compare":
            result = compare(args.target, args.candidate, args.map,
                             args.symbols_from, args.project_crate)
        else:
            result = judge(args.target, args.candidate, args.baseline, args.source,
                           args.map, args.baseline_map)
        if getattr(args, "out", None) and args.command in ("compare", "judge"):
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(result, indent=2) + "\n")
        shown = result
        if args.command == "compare" and args.out:
            shown = {k: v for k, v in result.items() if k != "functions"}
        if args.command == "judge" and args.out:
            shown = {**result, "current": {k: v for k, v in result["current"].items()
                                            if k != "functions"}}
        print(json.dumps(shown, indent=2))
        return 0 if args.command not in ("judge", "benchmark", "corpus-benchmark") or result["passed"] else 1
    except (ValueError, OSError, KeyError, IndexError, struct.error, urllib.error.URLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
