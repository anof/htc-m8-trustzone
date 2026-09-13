#!/usr/bin/env python3
"""wp_calls.py - enumerate every hboot call to partition_write_prot_mmc
(0x0f504a30) and recover its (start_partition, end_partition, mode) args.

mode = 1 -> arm the eMMC write protection, mode = 0 -> CLEAR it (unprotect).
Arguments are reconstructed by walking backwards from the call site,
resolving the ldr/add-pc string idiom and the last immediate load per
register, exactly as the compiler emitted them.
"""
import re
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x0F500000
d = open('/Users/azizdaoud/m8-soff/hboot.img', 'rb').read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
TARGET = 0x0f504a30


def cstr(va, ml=64):
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


def insns():
    out = []
    p = 0
    while p < len(d) - 4:
        i = next(md.disasm(d[p:p + 4], BASE + p), None)
        if i is None:
            p += 2
            continue
        out.append(i)
        p += i.size
    return out


def main():
    L = insns()
    calls = []
    for k, i in enumerate(L):
        if i.mnemonic in ('bl', 'blx') and i.op_str.startswith('#'):
            try:
                t = int(i.op_str[1:], 16) & ~1
            except ValueError:
                continue
            if t == TARGET:
                calls.append(k)
    print('%d call sites to partition_write_prot_mmc' % len(calls))
    for k in calls:
        regs = {}      # reg -> (kind, value)
        for j in range(k - 1, max(0, k - 40), -1):
            it = L[j]
            m = re.match(r'(r\d+), \[pc, #(0x[0-9a-f]+|\d+)\]', it.op_str)
            if it.mnemonic.startswith('ldr') and m:
                la = ((it.address + 4) & ~3) + int(m.group(2), 0)
                if BASE <= la < BASE + len(d) - 4:
                    val = struct.unpack_from('<I', d, la - BASE)[0]
                    regs.setdefault(m.group(1), ('lit', val, it.address))
                continue
            if it.mnemonic == 'add' and it.op_str.endswith(', pc'):
                reg = it.op_str.split(',')[0]
                if reg in regs and regs[reg][0] == 'lit' and regs[reg][1] < 0x2000000:
                    va = regs[reg][1] + it.address + 4
                    s = cstr(va)
                    if s:
                        regs[reg] = ('str', s, it.address)
                continue
            m = re.match(r'(r\d+), #(-?\d+|0x[0-9a-f]+)$', it.op_str)
            if m and it.mnemonic in ('movs', 'mov', 'mov.w'):
                regs[m.group(1)] = ('imm', int(m.group(2), 0), it.address)
                continue
            m = re.match(r'(r\d+), (r\d+)$', it.op_str)
            if m and it.mnemonic in ('mov', 'mov.w'):
                src = m.group(2)
                if src in regs:
                    regs[m.group(1)] = regs[src]
                continue
        r0 = regs.get('r0', ('?', 0, 0))
        r1 = regs.get('r1', ('?', 0, 0))
        r2 = regs.get('r2', ('?', 0, 0))
        print('%#010x  start=%-14s end=%-14s mode=%s' %
              (L[k].address,
               (r0[1] if r0[0] == 'str' else 'r0:%s' % r0[1]),
               (r1[1] if r1[0] == 'str' else 'r1:%s' % r1[1]),
               r2[1]))


if __name__ == '__main__':
    main()
