#!/usr/bin/env python3
"""qdiff.py <ours.img> <final.img> [--min N] [--show]

Instruction-level diff of two QSEE trustlet builds of the same app.

Both code segments are linear-swept in Thumb mode, each instruction is
normalised to "mnemonic + operand classes" (immediates -> #I, numbers -> I),
and the two token streams are aligned with difflib.  Because the builds are
the same program, alignment survives address shifts and insertions, so the
changed regions are exactly the vendor's later edits -- i.e. post-2016
security fixes -- which are by definition *absent* from our build.

Output: one block per changed region, with our VA range and the final VA
range, plus the instruction listings on both sides.
"""
import difflib
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

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
            return d[off:off + p[4]], p[2], p[4]
    raise SystemExit('no code segment in ' + path)


def nop_of(mnem, ops):
    out = []
    for op in ops.split(', '):
        if op.startswith('#'):
            # keep the immediate only when it is a small selector index,
            # which matters for dispatchers; otherwise mask it.
            v = op[1:]
            try:
                if int(v, 0) <= 0x40:
                    out.append('#s')
                    continue
            except ValueError:
                pass
            out.append('#I')
        elif op.startswith('0x') or op.isdigit():
            out.append('I')
        else:
            out.append(op)
    return mnem + ' ' + ', '.join(out)


def sweep(code, va):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    toks, insns = [], []
    p = 0
    while p < len(code) - 4:
        it = next(md.disasm(code[p:p + 4], va + p), None)
        if it is None:
            p += 2
            continue
        # a thumb 32-bit instruction lives in a 4-byte window; a 16-bit one
        # may be followed by a 16-bit instruction that capstone will merge
        # into nonsense, so re-disassemble that window from the 2-byte bound
        toks.append(nop_of(it.mnemonic, it.op_str))
        insns.append((it.address, it.mnemonic, it.op_str))
        p += it.size
    return toks, insns


def main():
    ours, finals = sys.argv[1], sys.argv[2]
    minrun = 1
    show = True
    if '--min' in sys.argv:
        minrun = int(sys.argv[sys.argv.index('--min') + 1])
    if '--nosh' in sys.argv:
        show = False
    ca, va, sa = load(ours)
    cb, vb, sb = load(finals)
    ta, ia = sweep(ca, va)
    tb, ib = sweep(cb, vb)
    sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    print('== %s (ours) vs %s (final)' % (ours, finals))
    print('== ours: %d insns @%#x..%#x | final: %d insns @%#x..%#x'
          % (len(ta), va, va + sa, len(tb), vb, vb + sb))
    ops = [o for o in sm.get_opcodes() if o[0] != 'equal']
    # merge opcodes separated by <= 4 equal instructions
    merged = []
    for o in ops:
        if merged and o[1] - merged[-1][2] <= 4:
            p = merged.pop()
            merged.append(('chg', p[1], o[2], p[3], o[4]))
        else:
            merged.append(('chg', o[1], o[2], o[3], o[4]))
    print('== changed regions: %d (raw opcodes %d)' % (len(merged), len(ops)))
    for k, (_, a1, a2, b1, b2) in enumerate(merged):
        if a2 - a1 < minrun and b2 - b1 < minrun:
            continue
        sa_ = '%#x' % ia[a1][0] if a1 < len(ia) else '-'
        ea_ = '%#x' % ia[a2 - 1][0] if a2 - 1 < len(ia) else '-'
        sb_ = '%#x' % ib[b1][0] if b1 < len(ib) else '-'
        eb_ = '%#x' % ib[b2 - 1][0] if b2 - 1 < len(ib) else '-'
        print('\n--- region %d: ours %s..%s (%d) | final %s..%s (%d)'
              % (k, sa_, ea_, a2 - a1, sb_, eb_, b2 - b1))
        if show:
            for m, table, start in (('-', ia, a1), ('+', ib, b1)):
                n = (a2 - a1) if m == '-' else (b2 - b1)
                for i in range(start, start + min(n, 24)):
                    if i < len(table):
                        t = table[i]
                        print('    %s %#010x  %-8s %s' % (m, t[0], t[1], t[2]))
                if n > 24:
                    print('    %s  ... (%d more)' % (m, n - 24))
        # print ours-only and final-only counts
        print('    [ours removed? %d instrs, final added? %d instrs]'
              % (a2 - a1, b2 - b1))
    return 0


if __name__ == '__main__':
    main()
