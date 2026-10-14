"""Disassemble R3000 (PS1) code from the EXE, an overlay, or a RAM dump.

Usage (needs capstone; uv fetches it into a throwaway env):
  uv run --with capstone python tools/mipsdis.py FILE BASE ADDR COUNT

FILE is mapped so that file offset 0 is at address BASE:
  SLPM_86.053            BASE=0x80040800  (0x800-byte header, loads at 0x80041000)
  CDROM/EXEDIR/*.EXN     BASE=0x80132000
  2 MB RAM dump          BASE=0x80000000
"""

import sys

import capstone

path, base, addr, count = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), int(sys.argv[4], 0)
md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN)
data = open(path, "rb").read()
off = addr - base
for insn in md.disasm(data[off:off + count * 4], addr):
    print(f"{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}")
