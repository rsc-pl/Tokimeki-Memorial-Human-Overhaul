"""A minimal MIPS I (R3000) assembler for the patcher's code hooks.

Only what the hooks need: one instruction per line, labels, `%hi()`/`%lo()`
of symbols, and no pseudo-instructions that expand to more than one word.
The R3000 has a branch delay slot and a load delay slot; the source must
handle both itself (the assembler doesn't reorder or insert nops).

    code = assemble('''
        loop:
            addiu t0, t0, -1
            bnez  t0, loop
            nop
    ''', origin=0x80044000)
"""

from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional

REGS = {name: i for i, name in enumerate(
    "zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 "
    "s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra".split())}

# name: (kind, opcode, funct)
OPS = {
    "sll": ("shift", 0, 0x00), "srl": ("shift", 0, 0x02), "sra": ("shift", 0, 0x03),
    "addu": ("r3", 0, 0x21), "subu": ("r3", 0, 0x23), "and": ("r3", 0, 0x24),
    "or": ("r3", 0, 0x25), "xor": ("r3", 0, 0x26), "slt": ("r3", 0, 0x2A),
    "sltu": ("r3", 0, 0x2B),
    "addiu": ("imm", 0x09, 0), "slti": ("imm", 0x0A, 0), "sltiu": ("imm", 0x0B, 0),
    "andi": ("imm", 0x0C, 0), "ori": ("imm", 0x0D, 0),
    "lui": ("lui", 0x0F, 0),
    "lb": ("mem", 0x20, 0), "lh": ("mem", 0x21, 0), "lw": ("mem", 0x23, 0),
    "lbu": ("mem", 0x24, 0), "lhu": ("mem", 0x25, 0),
    "sb": ("mem", 0x28, 0), "sh": ("mem", 0x29, 0), "sw": ("mem", 0x2B, 0),
    "beq": ("branch2", 0x04, 0), "bne": ("branch2", 0x05, 0),
    "beqz": ("branch1", 0x04, 0), "bnez": ("branch1", 0x05, 0),
    "j": ("jump", 0x02, 0), "jal": ("jump", 0x03, 0),
    "jr": ("jr", 0, 0x08),
    "move": ("move", 0, 0x21), "nop": ("nop", 0, 0),
}


def _reg(text: str) -> int:
    name = text.strip().lstrip("$")
    if name not in REGS:
        raise ValueError(f"unknown register {text!r}")
    return REGS[name]


def _value(text: str, symbols: Dict[str, int]) -> int:
    text = text.strip()
    m = re.fullmatch(r"%(hi|lo)\((.+)\)", text)
    if m:
        v = _value(m.group(2), symbols)
        return ((v + 0x8000) >> 16) & 0xFFFF if m.group(1) == "hi" else v & 0xFFFF
    if text in symbols:
        return symbols[text]
    try:
        return int(text, 0)
    except ValueError:
        raise ValueError(f"unknown symbol {text!r}") from None


def _imm16(v: int, signed: bool) -> int:
    lo, hi = (-0x8000, 0xFFFF) if signed else (0, 0xFFFF)
    if not lo <= v <= hi:
        raise ValueError(f"immediate {v:#x} doesn't fit in 16 bits")
    return v & 0xFFFF


def _lines(source: str):
    for raw in source.splitlines():
        line = raw.split("#")[0].split(";")[0].strip()
        while line:
            m = re.match(r"([A-Za-z_]\w*):\s*(.*)", line)
            if not m:
                yield line
                break
            yield m.group(1) + ":"
            line = m.group(2).strip()


def assemble(source: str, origin: int, symbols: Optional[Dict[str, int]] = None) -> bytes:
    """Assemble `source` to be placed at address `origin`. Returns the code."""
    symbols = dict(symbols or {})
    insns: List[str] = []
    for line in _lines(source):
        if line.endswith(":"):
            label = line[:-1]
            if label in symbols:
                raise ValueError(f"duplicate label {label!r}")
            symbols[label] = origin + 4 * len(insns)
        else:
            insns.append(line)

    out = bytearray()
    for i, line in enumerate(insns):
        pc = origin + 4 * i
        name, _, rest = line.partition(" ")
        args = [a.strip() for a in rest.split(",")] if rest.strip() else []
        if name not in OPS:
            raise ValueError(f"unknown instruction {line!r}")
        kind, op, funct = OPS[name]
        try:
            if kind == "nop":
                word = 0
            elif kind == "shift":
                rd, rt, sa = _reg(args[0]), _reg(args[1]), _value(args[2], symbols)
                if not 0 <= sa < 32:
                    raise ValueError("shift amount out of range")
                word = (rt << 16) | (rd << 11) | (sa << 6) | funct
            elif kind == "r3":
                rd, rs, rt = (_reg(a) for a in args)
                word = (rs << 21) | (rt << 16) | (rd << 11) | funct
            elif kind == "move":
                rd, rs = _reg(args[0]), _reg(args[1])
                word = (rs << 21) | (rd << 11) | funct
            elif kind == "imm":
                rt, rs = _reg(args[0]), _reg(args[1])
                v = _value(args[2], symbols)
                word = (op << 26) | (rs << 21) | (rt << 16) | _imm16(v, signed=op in (0x09, 0x0A, 0x0B))
            elif kind == "lui":
                word = (op << 26) | (_reg(args[0]) << 16) | _imm16(_value(args[1], symbols), False)
            elif kind == "mem":
                m = re.fullmatch(r"(.*)\((.+)\)", args[1])
                if not m:
                    raise ValueError("expected offset(base)")
                v = _value(m.group(1) or "0", symbols)
                if v >= 0x8000 and v <= 0xFFFF:   # %lo() of an address: a signed offset
                    v -= 0x10000
                word = (op << 26) | (_reg(m.group(2)) << 21) | (_reg(args[0]) << 16) | _imm16(v, True)
            elif kind in ("branch1", "branch2"):
                rs = _reg(args[0])
                rt = _reg(args[1]) if kind == "branch2" else 0
                target = _value(args[-1], symbols)
                delta = target - (pc + 4)
                if delta % 4:
                    raise ValueError("misaligned branch target")
                word = (op << 26) | (rs << 21) | (rt << 16) | _imm16(delta >> 2, True)
            elif kind == "jump":
                target = _value(args[0], symbols)
                if target % 4 or (target & 0xF0000000) != ((pc + 4) & 0xF0000000):
                    raise ValueError(f"jump target {target:#x} unreachable from {pc:#x}")
                word = (op << 26) | ((target >> 2) & 0x3FFFFFF)
            elif kind == "jr":
                word = (_reg(args[0]) << 21) | funct
            else:  # pragma: no cover
                raise AssertionError(kind)
        except (ValueError, IndexError) as e:
            raise ValueError(f"{line!r}: {e}") from None
        out += struct.pack("<I", word)
    return bytes(out)
