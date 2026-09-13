#!/usr/bin/env python3
"""Robust PC-relative string/data xref finder.
usage: xrefs.py 0x0f5881e4 [more VAs]
"""
import struct, sys
from capstone import *
from capstone.arm import *

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True
n = len(d)
STOP = {'b', 'bl', 'bx', 'blx', 'pop', 'pop.w', 'push', 'push.w'}


def cstr(va, ml=80):
    off = va - BASE
    if not (0 <= off < n):
        return None
    e = d.find(b'\x00', off)
    if e < 0 or e - off > ml:
        return None
    t = d[off:e]
    if not t or any(c < 0x20 or c > 0x7e for c in t):
        return None
    return t.decode()


def xrefs(target):
    out = []
    off = 0
    while off < n - 8:
        ins = list(md.disasm(d[off:off + 4], BASE + off))
        if not ins:
            off += 2
            continue
        i = ins[0]
        if i.mnemonic in ('ldr', 'ldr.w'):
            o = i.operands
            if len(o) >= 2 and o[1].type == ARM_OP_MEM and o[1].mem.base == ARM_REG_PC:
                lit = ((i.address + 4) & ~3) + o[1].mem.disp
                if 0 <= lit - BASE < n - 4:
                    L = struct.unpack_from('<I', d, lit - BASE)[0]
                    reg = i.reg_name(o[0].reg)
                    q = off + i.size
                    for _ in range(6):
                        nxt = list(md.disasm(d[q:q + 4], BASE + q))
                        if not nxt:
                            break
                        j = nxt[0]
                        if j.mnemonic == 'add' and j.op_str.startswith(reg + ',') and 'pc' in j.op_str:
                            va = L + j.address + 4
                            if va == target:
                                out.append((i.address, j.address))
                            break
                        if j.mnemonic in STOP:
                            break
                        q += j.size
        off += i.size
    return out


if __name__ == '__main__':
    for a in sys.argv[1:]:
        t = int(a, 16)
        r = xrefs(t)
        print(f"{t:#010x} {cstr(t)!r}  <- {len(r)} site(s)")
        for ca, aa in r:
            print(f"    ldr @ {ca:#010x}   add @ {aa:#010x}")
