#!/usr/bin/env python3
"""fdiff_detail.py <ours.img> <final.img>

For every function that differs between the two builds, find the best-matching
function in the other build (difflib over normalised instructions) and print
the differing instruction windows, i.e. what the newer build added/changed.
"""
import difflib
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

FIX = 0x4B8


def code_seg(path):
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


def sweep(code, va):
    """Return {va: (mnemonic, op_str)} for every decodable instruction."""
    insns = {}
    for mode in (CS_MODE_THUMB, CS_MODE_ARM):
        md = Cs(CS_ARCH_ARM, mode)
        p = 0
        while p < len(code) - 4:
            it = next(md.disasm(code[p:p + 4], va + p), None)
            if it is None:
                p += 2
                continue
            if it.address not in insns:
                insns[it.address] = (it.mnemonic, it.op_str, mode)
            p += it.size
    return insns


def norm(mn, ops):
    parts = []
    for op in ops.split(', '):
        if op.startswith('#'):
            parts.append('#I')
        elif op.startswith('0x') or op.isdigit():
            parts.append('I')
        else:
            parts.append(op)
    return mn + ' ' + ', '.join(parts)


def functions(path):
    code, va = code_seg(path)
    insns = sweep(code, va)
    bls = {a for a, (m, o, _) in insns.items()
           if m in ('bl', 'blx') and o.startswith('#')}
    tg = set()
    for a, (m, o, _) in insns.items():
        if m in ('bl', 'blx') and o.startswith('#'):
            try:
                tg.add(int(o[1:], 16))
            except ValueError:
                pass
    starts = sorted({va} | {t for t in tg if va <= t < va + len(code)})
    out = []
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else va + len(code)
        seq = [norm(*insns[a][:2]) for a in sorted(insns) if s <= a < e]
        if seq:
            out.append((s, e - s, seq))
    return out


def main():
    a = functions(sys.argv[1])
    b = functions(sys.argv[2])
    ah = {tuple(x[2]) for x in a}
    for s, sz, seq in b:
        if tuple(seq) in ah:
            continue
        best = None
        for s2, sz2, seq2 in a:
            r = difflib.SequenceMatcher(None, seq2, seq, autojunk=False)
            score = r.ratio()
            if best is None or score > best[0]:
                best = (score, s2, sz2, seq2)
        score, s2, sz2, seq2 = best
        print('=== final va=%#x size=%#x (%d insns)  best match ours va=%#x size=%#x  ratio=%.3f'
              % (s, sz, len(seq), s2, sz2, score))
        sm = difflib.SequenceMatcher(None, seq2, seq, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                continue
            print('   %-8s ours[%d:%d] -> final[%d:%d]' % (tag, i1, i2, j1, j2))
            for line in seq2[i1:i2][:14]:
                print('      - %s' % line)
            for line in seq[j1:j2][:14]:
                print('      + %s' % line)
        print()


if __name__ == '__main__':
    main()
