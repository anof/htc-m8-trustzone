#!/usr/bin/env python3
"""Recursive-descent walker for the HTC M8 hboot image.

hboot.img header says it loads at 0x0F500000. Code is predominantly Thumb.
Walk from a given address, following BL/BLX targets, and print annotated
disassembly with resolved string references.
"""
import struct, sys
from capstone import *
from capstone.arm import *

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()
mdT = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
mdT.detail = True
mdA = Cs(CS_ARCH_ARM, CS_MODE_ARM)
mdA.detail = True


def cstr(va, ml=48):
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


def walk(start, maxins=120, depth=0, seen=None, label=""):
    if seen is None:
        seen = set()
    va = start & ~1
    if va in seen or depth > 2:
        return
    seen.add(va)
    off = va - BASE
    if not (0 <= off < len(d)):
        print(f"{'  '*depth};; {va:#010x} OUT OF RANGE")
        return
    pad = '  ' * depth
    print(f"\n{pad}===== {label} {va:#010x} =====")
    md = mdT if (start & 1) else mdA
    n = 0
    calls = []
    for i in md.disasm(d[off:off + maxins * 4], va):
        note = ''
        # resolve literal pool loads and branch targets
        if i.mnemonic in ('bl', 'blx') and i.operands and i.operands[0].type == ARM_OP_IMM:
            t = i.operands[0].imm & 0xffffffff
            calls.append(t)
            note = f'   -> {t:#010x}'
        if i.mnemonic in ('ldr', 'ldr.w') and i.operands and len(i.operands) == 2:
            if i.operands[1].type == ARM_OP_MEM and i.operands[1].mem.base == ARM_REG_PC:
                # load from literal pool
                try:
                    lit = i.address + 4 + i.operands[1].mem.disp
                    lit &= ~3
                    if 0 <= lit - BASE < len(d) - 4:
                        val = struct.unpack_from('<I', d, lit - BASE)[0]
                        s = cstr(val)
                        addr_note = f' [lit {val:#010x}]'
                        if s:
                            addr_note += f' "{s}"'
                        note = addr_note
                except Exception:
                    pass
        # add pc-relative string hints
        if i.mnemonic in ('add', 'adr') and 'pc' in i.op_str:
            note = note or '   (pc-relative)'
        print(f"{pad}  {i.address:#010x}  {i.bytes.hex():<10} {i.mnemonic:<8} {i.op_str}{note}")
        n += 1
        if i.mnemonic in ('bx', 'pop') and ('lr' in i.op_str or 'pc' in i.op_str):
            break
        if i.mnemonic.startswith('b') and i.mnemonic != 'bl' and i.mnemonic != 'blx':
            if i.operands and i.operands[0].type == ARM_OP_IMM:
                t = i.operands[0].imm & 0xffffffff
                if not (va <= t < va + 0x400):
                    break
    for t in dict.fromkeys(calls):
        walk(t, maxins=60, depth=depth + 1, seen=seen, label="call")


if __name__ == '__main__':
    targets = {
        'readsecureflag':   (0x0f5156ad, 'thumb'),
        'writesecureflag':  (0x0f515b65, 'thumb'),
        'writecid':         (0x0f515329, 'thumb'),
        'get_id_token':     (0x0f514f39, 'thumb'),
        'checkKeycardID':   (0x0f514f1d, 'thumb'),
        'readcid':          (0x0f515e29, 'thumb'),
    }
    which = sys.argv[1:] or list(targets.keys())
    for name in which:
        if name in targets:
            a, m = targets[name]
            walk(a, maxins=90, label=name)
