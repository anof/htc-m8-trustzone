#!/usr/bin/env python3
"""Linear-sweep the whole image and report all BL/BLX call sites per target.
usage: blrefs.py 0xf50d5ec [more targets]
"""
import sys
from capstone import *

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True
calls = {}
off = 0
n = len(d)
while off < n - 4:
    ins = next(md.disasm(d[off:off + 4], BASE + off), None)
    if ins is None:
        off += 2
        continue
    if ins.mnemonic in ('bl', 'blx') and ins.operands and ins.operands[0].type == 2:
        t = ins.operands[0].imm & ~1
        calls.setdefault(t, []).append(ins.address)
    off += ins.size

for a in sys.argv[1:]:
    t = int(a, 16)
    sites = calls.get(t, [])
    print(f"{t:#010x}: {len(sites)} call site(s)")
    for s in sites:
        print(f"    {s:#010x}")
