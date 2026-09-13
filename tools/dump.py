#!/usr/bin/env python3
"""Linear disassembler for hboot ranges with string + call annotations.

usage: dump.py 0x0f514460 [0xnnn length | stopaddr]
Annotates: pc-relative string loads (via resolve-style logic), BL/BLX targets,
and indirect calls through literal pools (blx rN).
"""
import struct, sys
from capstone import *
from capstone.arm import *

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True


def cstr(va, ml=64):
    off = va - BASE
    if not (0 <= off < len(d)):
        return None
    e = d.find(b'\x00', off)
    if e < 0 or e - off > ml:
        return None
    t = d[off:e]
    if not t or any(c < 0x20 or c > 0x7e for c in t):
        return None
    return t.decode()


def annot(ins, addr):
    notes = []
    for op in ins.operands:
        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
            lit = ((addr + 4) & ~3) + op.mem.disp
            if 0 <= lit - BASE < len(d) - 4:
                L = struct.unpack_from('<I', d, lit - BASE)[0]
                notes.append(f"[lit {L:#x}]")
                # try +pc idiom: literal is an offset added to pc later
                s = cstr(L)
                if s:
                    notes.append(f'"{s}"')
        if op.type == ARM_OP_IMM and ins.mnemonic in ('bl', 'blx'):
            t = op.imm
            if t & 1:
                notes.append(f"-> thumb {t & ~1:#x}")
    return notes


def main():
    start = int(sys.argv[1], 16)
    arg2 = sys.argv[2] if len(sys.argv) > 2 else "0x400"
    v = int(arg2, 16) if arg2.startswith('0x') else int(arg2)
    end = v if (v > start) else None
    n = None if end else v
    off = start - BASE
    code = d[off:] if n is None else d[off:off + n]
    stop = end if end else start + len(code)
    for ins in md.disasm(code, start):
        if ins.address >= stop:
            break
        notes = annot(ins, ins.address)
        line = f"{ins.address:#010x}  {ins.bytes.hex():<10} {ins.mnemonic:<7} {ins.op_str}"
        if notes:
            line += "   ; " + " ".join(notes)
        print(line)


if __name__ == '__main__':
    main()
