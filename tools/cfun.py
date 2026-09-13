#!/usr/bin/env python3
"""cfun.py <addr> <length> [--arm]

Annotated Thumb disassembly of an hboot range: resolves the HTC PC-relative
string idiom (ldr rX,[pc,#d] ; add rX,pc), BL/BLX targets, literal-pool
contents and immediate loads, so a function can be read without a GUI.
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()


def cstr(va, ml=96):
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


def litval(ins):
    """If ins is ldr rX,[pc,#d] return (reg, literal_address, value)."""
    m = re.match(r'(r\d+|sb|sl|fp|ip|sp|lr), \[pc, #(0x[0-9a-f]+|\d+)\]', ins.op_str)
    if not m or not ins.mnemonic.startswith('ldr'):
        return None
    disp = int(m.group(2), 0)
    la = ((ins.address + 4) & ~3) + disp
    if not (BASE <= la < BASE + len(d) - 4):
        return None
    return m.group(1), la, struct.unpack_from('<I', d, la - BASE)[0]


def main():
    va = int(sys.argv[1], 16)
    ln = int(sys.argv[2], 0)
    mode = CS_MODE_ARM if '--arm' in sys.argv else CS_MODE_THUMB
    md = Cs(CS_ARCH_ARM, mode)
    md.detail = False
    p0 = va - BASE
    p = p0
    pend = p0 + ln
    pending = {}
    while p < pend:
        ins = next(md.disasm(d[p:p + 4], BASE + p), None)
        if ins is None:
            p += 2
            continue
        note = ''
        lv = litval(ins)
        if lv:
            reg, la, val = lv
            pending[reg] = (la, val, ins.address)
            note = '  ; [lit@%#x = %#x]' % (la, val)
        if ins.mnemonic == 'add' and ins.op_str.endswith(', pc'):
            reg = ins.op_str.split(',')[0]
            if reg in pending:
                la, val, src = pending[reg]
                t = val + ins.address + 4
                s = cstr(t)
                if s is not None:
                    note = '  ; -> %#x "%s"' % (t, s)
                else:
                    note = '  ; -> %#x' % t
            else:
                # plain adr-style: add rX, pc = pc + rX
                note = '  ; adr?'
        elif ins.mnemonic in ('bl', 'blx') and ins.op_str.startswith('#'):
            note = '  ; call %s' % ins.op_str
        elif ins.mnemonic == 'movw' or ins.mnemonic == 'movs':
            pass
        print('%#010x  %-8s %-28s%s' % (ins.address, ins.mnemonic, ins.op_str, note))
        p += ins.size


if __name__ == '__main__':
    main()
