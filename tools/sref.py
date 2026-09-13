#!/usr/bin/env python3
"""sref.py "substring" [-w 0x40] [-n 4]

Find every code reference to a string in hboot.img and disassemble around
each reference site.

Method: hboot loads strings with the PC-relative idiom
    ldr rX, [pc, #d]      ; rX = offset
    add rX, pc            ; rX = offset + (addr_of_add + 4)
so for a string at absolute address S, every literal word W in the image
that satisfies W = S - (A + 4) for a site A that decodes as `add rX, pc`
is a reference.  This is drift-free and finds refs the linear sweep misses.
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x0F500000
IMG = '/Users/azizdaoud/m8-soff/hboot.img'


def load():
    return open(IMG, 'rb').read()


def dis(d, va, n=8):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    p = va - BASE
    out = []
    for _ in range(n):
        it = next(md.disasm(d[p:p + 4], va + (p - (va - BASE))), None)
        if it is None:
            p += 2
            continue
        out.append('  %#010x  %-8s %s' % (it.address, it.mnemonic, it.op_str))
        p += it.size
    return out


def find_refs(d, sva):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    refs = []
    for i in range(0, len(d) - 4, 2):
        W = struct.unpack_from('<I', d, i)[0]
        if W == 0 or W > 0x200000:
            continue
        A = (sva - 4 - W) & 0xFFFFFFFF
        if not (BASE <= A < BASE + len(d)):
            continue
        ai = A - BASE
        it = next(md.disasm(d[ai:ai + 4], A), None)
        if it and it.mnemonic == 'add' and it.op_str.endswith(', pc'):
            # verify the ldr that feeds it is within 12 bytes before
            ok = False
            reg = it.op_str.split(',')[0]
            for back in (4, 6, 8, 10, 12):
                if ai - back < 0:
                    break
                p = next(md.disasm(d[ai - back:ai - back + 4], A - back), None)
                if p and p.mnemonic.startswith('ldr') and p.op_str.startswith(reg + ','):
                    ok = True
                    break
            refs.append((A, ok))
    return refs


def main():
    needle = sys.argv[1].encode()
    width = 0x40
    if '-w' in sys.argv:
        width = int(sys.argv[sys.argv.index('-w') + 1], 0)
    d = load()
    n = 0
    off = 0
    while True:
        off = d.find(needle, off)
        if off < 0:
            break
        sva = BASE + off
        s = d[off:d.find(b'\x00', off)].decode('latin1')
        print('STR %#x  "%s"' % (sva, s))
        for A, ok in find_refs(d, sva):
            print('  ref at %#x%s' % (A, '' if ok else ' (unconfirmed)'))
            if width:
                for line in dis(d, A - width // 2, width // 2):
                    print(line)
        n += 1
        off += 1
    if not n:
        print('string not found')


if __name__ == '__main__':
    main()
