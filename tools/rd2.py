#!/usr/bin/env python3
"""rd2.py <trustlet.img> [out.json]

Call-graph disassembler for QSEE trustlets: starts at the ELF entry (ARM),
decodes each function linearly in the mode inherited from its caller (blx
switches to Thumb when the target has bit 0 set) and recurses into direct
calls. Produces per-function instruction listings in the correct mode for a
content-based diff between two builds.
"""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

FIX = 0x4B8


def load(path):
    d = open(path, 'rb').read()
    mdt = d[:6748]
    e_entry = struct.unpack_from('<I', mdt, 0x18)[0]
    e_phoff = struct.unpack_from('<I', mdt, 0x1c)[0]
    e_phnum = struct.unpack_from('<H', mdt, 0x2c)[0]
    for i in range(e_phnum):
        p = struct.unpack_from('<8I', mdt, e_phoff + i * 32)
        if p[0] == 1 and (p[6] & 1):
            off = p[1] + FIX
            return d[off:off + p[4]], p[2], p[4], e_entry
    raise SystemExit('no code segment')


def main():
    code, code_va, code_sz, entry = load(sys.argv[1])
    out_path = sys.argv[2] if len(sys.argv) > 2 else '/tmp/funcs.json'
    end = code_va + code_sz
    mdA = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    mdT = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    funcs = {}
    work = [(entry, CS_MODE_ARM)]
    while work:
        va, mode = work.pop()
        if va in funcs or not (code_va <= va < end):
            continue
        md = mdA if mode == CS_MODE_ARM else mdT
        seq = []
        cur = va
        while code_va <= cur < end:
            off = cur - code_va
            it = next(md.disasm(code[off:off + 4], cur), None)
            if it is None:
                break
            seq.append([cur, it.mnemonic, it.op_str])
            m, ops = it.mnemonic, it.op_str
            nxt = cur + it.size
            if m in ('bl', 'blx') and ops.startswith('#'):
                try:
                    t = int(ops[1:], 16)
                except ValueError:
                    t = None
                if t is not None and code_va <= t < end:
                    if m == 'blx':
                        work.append((t & ~1, CS_MODE_THUMB if (t & 1) else CS_MODE_ARM))
                    else:
                        work.append((t, mode))
                cur = nxt
                continue
            if m in ('b', 'bx') and ops.startswith('#'):
                try:
                    t = int(ops[1:], 16)
                except ValueError:
                    t = None
                if t is not None and code_va <= t < end:
                    work.append((t, mode))
                break
            if m == 'pop':
                if 'pc' in ops:
                    break
                cur = nxt
                continue
            if m == 'bx':
                break
            if m == 'ldr' and 'pc' in ops:
                break
            cur = nxt
        funcs['%#x' % va] = seq
    with open(out_path, 'w') as f:
        json.dump(funcs, f)
    total = sum(len(v) for v in funcs.values())
    print('%s: entry=%#x code=%d bytes  funcs=%d insns=%d'
          % (sys.argv[1], entry, code_sz, len(funcs), total))


if __name__ == '__main__':
    main()
