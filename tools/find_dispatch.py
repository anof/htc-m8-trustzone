#!/usr/bin/env python3
"""find_dispatch.py <trustlet.img>

Finds a command dispatcher of the shape
    cmp.w rX, #1 / beq A ; cmp.w rX, #2 / beq B ; cmp.w rX, #3 / beq C
and prints the register, the compare site and the three branch targets
(+4 = body of the handler stub).
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

FIX = 0x4B8


def load(path):
    d = open(path, 'rb').read()
    mdt = d[:6748]
    e_phoff = struct.unpack_from('<I', mdt, 0x1c)[0]
    e_phnum = struct.unpack_from('<H', mdt, 0x2c)[0]
    for i in range(e_phnum):
        p = struct.unpack_from('<8I', mdt, e_phoff + i * 32)
        if p[0] == 1 and (p[6] & 1):
            off = p[1] + FIX
            return d[off:off + p[4]], p[2]
    raise SystemExit('no code segment')


def main():
    code, va = load(sys.argv[1])
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    insns = []
    p = 0
    while p < len(code) - 4:
        it = next(md.disasm(code[p:p + 4], va + p), None)
        if it is None:
            p += 2
            continue
        insns.append(it)
        p += it.size
    for i in range(len(insns) - 5):
        a = insns[i]
        if a.mnemonic not in ('cmp', 'cmp.w') or '#' not in a.op_str:
            continue
        parts = a.op_str.split(', ')
        if len(parts) < 2:
            continue
        reg, imm = parts[0], parts[1]
        if imm not in ('#1', '#2', '#3'):
            continue
        win = insns[i:i + 8]
        want = ['#1', '#2', '#3']
        seen = []
        for w in win:
            if w.mnemonic in ('cmp', 'cmp.w') and w.op_str.startswith(reg + ', '):
                seen.append(w.op_str.split(', ')[1])
        if seen[:3] != want:
            continue
        tgts = []
        for w in win:
            if w.mnemonic == 'beq' and w.op_str.startswith('#'):
                tgts.append(int(w.op_str[1:], 16))
        if len(tgts) >= 3:
            print('%s: dispatch @%#x reg=%s cmds 1,2,3 -> handler stubs %s'
                  % (sys.argv[1], a.address, reg, [hex(t) for t in tgts[:3]]))
    return 0


if __name__ == '__main__':
    main()
