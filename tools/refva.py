#!/usr/bin/env python3
"""Find code sites that materialise an arbitrary VA via ldr-literal + add rX,pc.
usage: refva.py 0x0f6a3a8c [more VAs...]
Also reports plain literal-pool hits for the target (word stored in image).
"""
import struct, sys
from capstone import *
from capstone.arm import *

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True
n = len(d)


def scan(target):
    hits = []
    for off in range(0, n - 8, 2):
        ins = list(md.disasm(d[off:off + 4], BASE + off))
        if not ins:
            continue
        i = ins[0]
        if i.mnemonic not in ('ldr', 'ldr.w'):
            continue
        o = i.operands
        if len(o) < 2 or o[1].type != ARM_OP_MEM or o[1].mem.base != ARM_REG_PC:
            continue
        lit = ((i.address + 4) & ~3) + o[1].mem.disp
        if not (0 <= lit - BASE < n - 4):
            continue
        L = struct.unpack_from('<I', d, lit - BASE)[0]
        reg = i.reg_name(o[0].reg)
        p = off + i.size
        for _ in range(4):
            nxt = list(md.disasm(d[p:p + 4], BASE + p))
            if not nxt:
                break
            j = nxt[0]
            if j.mnemonic == 'add' and j.op_str.startswith(reg + ',') and 'pc' in j.op_str:
                va = L + j.address + 4
                if va == target:
                    hits.append(('add-pc', i.address, L, lit))
                break
            if j.mnemonic in ('ldr', 'str', 'bl', 'blx', 'bx'):
                break
            p += j.size
    # plain pointer-in-data hits
    tgt_le = struct.pack('<I', target)
    p = 0
    while True:
        k = d.find(tgt_le, p)
        if k < 0:
            break
        hits.append(('word', BASE + k, target, k))
        p = k + 1
    return hits


if __name__ == '__main__':
    for a in sys.argv[1:]:
        t = int(a, 16)
        print(f"=== refs to {t:#x} ===")
        for kind, site, L, extra in scan(t)[:40]:
            print(f"  {kind:6} @ {site:#010x}  lit {L:#x}  ({extra:#x})")
