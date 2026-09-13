#!/usr/bin/env python3
"""fdiff.py - function-level diff between our trustlets and the M8-final build.

Function starts are taken from BL/BLX targets (resynchronising sweep in both
ARM and Thumb). Each function is hashed by its normalised instruction stream
so that address shifts between builds do not matter. Output lists functions
that exist only in one side.
"""
import hashlib
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
    raise SystemExit('no code segment in ' + path)


def call_targets(code, va):
    tg = set()
    for mode in (CS_MODE_THUMB, CS_MODE_ARM):
        md = Cs(CS_ARCH_ARM, mode)
        p = 0
        while p < len(code) - 4:
            it = next(md.disasm(code[p:p + 4], va + p), None)
            if it is None:
                p += 2
                continue
            if it.mnemonic in ('bl', 'blx') and it.op_str.startswith('#'):
                try:
                    tg.add(int(it.op_str[1:], 16))
                except ValueError:
                    pass
            p += it.size
    return tg


def normalise(it):
    ops = []
    for op in it.op_str.split(', '):
        if op.startswith('#'):
            ops.append('#I')
        elif op.startswith('0x') or op.isdigit():
            ops.append('I')
        else:
            ops.append(op)
    return it.mnemonic + ' ' + ', '.join(ops)


def func_hash(code, va, start, end):
    body = code[start:end]
    best = None
    for mode in (CS_MODE_THUMB, CS_MODE_ARM):
        md = Cs(CS_ARCH_ARM, mode)
        h = hashlib.sha1()
        n = 0
        for it in md.disasm(body, 0):
            h.update(normalise(it).encode())
            h.update(b';')
            n += 1
        if n and (best is None or n > best[1]):
            best = (h.hexdigest()[:16], n)
    return best


def functions(path):
    code, va = code_seg(path)
    tg = {t for t in call_targets(code, va) if va <= t < va + len(code)}
    starts = sorted({va} | tg)
    out = {}
    for i, s in enumerate(starts):
        e = starts[i + 1] if i + 1 < len(starts) else va + len(code)
        r = func_hash(code, va, s - va, e - va)
        if r:
            out.setdefault(r[0], []).append((s, e - s, r[1]))
    return out, code, va


def main():
    ours, finals = sys.argv[1], sys.argv[2]
    fa, ca, va = functions(ours)
    fb, cb, vb = functions(finals)
    only_final = sorted(set(fb) - set(fa))
    only_ours = sorted(set(fa) - set(fb))
    shared = set(fa) & set(fb)
    print('%s vs %s' % (ours, finals))
    print('  functions: ours=%d final=%d shared=%d only_final=%d only_ours=%d'
          % (len(fa), len(fb), len(shared), len(only_final), len(only_ours)))
    print('  functions only in the final build (candidate fixes):')
    for h in only_final[:60]:
        for s, sz, n in fb[h]:
            print('    %s  va=%#x size=%#x insns=%d' % (h, s, sz, n))


if __name__ == '__main__':
    main()
