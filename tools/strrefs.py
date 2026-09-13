#!/usr/bin/env python3
"""Print every PC-relative string reference inside an address range.
usage: strrefs.py start end
"""
import struct, sys
from capstone import *
from capstone.arm import *

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True


def cstr(va, ml=90):
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


def refs_in(off0, off1):
    p = off0
    while p < off1 - 4:
        ins = list(md.disasm(d[p:p + 4], BASE + p))
        if not ins:
            p += 2
            continue
        i = ins[0]
        if i.mnemonic in ('ldr', 'ldr.w'):
            o = i.operands
            if len(o) >= 2 and o[1].type == ARM_OP_MEM and o[1].mem.base == ARM_REG_PC:
                lit = ((i.address + 4) & ~3) + o[1].mem.disp
                if 0 <= lit - BASE < len(d) - 4:
                    L = struct.unpack_from('<I', d, lit - BASE)[0]
                    reg = i.reg_name(o[0].reg)
                    q = p + i.size
                    for _ in range(8):
                        nxt = list(md.disasm(d[q:q + 4], BASE + q))
                        if not nxt:
                            break
                        j = nxt[0]
                        if j.mnemonic == 'add' and j.op_str.startswith(reg + ',') and 'pc' in j.op_str:
                            va = L + j.address + 4
                            s = cstr(va)
                            if s:
                                yield (i.address, va, s)
                            break
                        if j.mnemonic in ('ldr', 'ldr.w', 'mov', 'movs', 'mov.w'):
                            q += j.size
                            continue
                        break
        p += i.size


if __name__ == '__main__':
    a, b = int(sys.argv[1], 16), int(sys.argv[2], 16)
    for ca, va, s in refs_in(a - BASE, b - BASE):
        print(f"{ca:#010x} -> {va:#010x}  {s!r}")
