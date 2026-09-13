#!/usr/bin/env python3
"""Resolve hboot's PC-relative string references.
   ldr.w rX,[pc,#imm]  -> literal at Align(addr+4,4)+imm
   add rX, pc          -> final = literal + (addr_of_add + 4)
"""
import struct, sys
from capstone import *
from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
BASE=0x0F500000
d=open('/Users/azizdaoud/m8-soff/hboot.img','rb').read()
md=Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail=True
def cstr(va,ml=60):
    off=va-BASE
    if not (0<=off<len(d)): return None
    e=d.find(b'\x00',off)
    if e<0 or e-off>ml: return None
    t=d[off:e]
    if not t or any(c<0x20 or c>0x7e for c in t): return None
    return t.decode()
def resolve_at(va):
    off=va-BASE
    ins=list(md.disasm(d[off:off+0x10], va))
    if not ins or ins[0].mnemonic not in ('ldr.w','ldr'): return None
    o=ins[0].operands
    if len(o)<2 or o[1].type!=ARM_OP_MEM or o[1].mem.base!=ARM_REG_PC: return None
    lit=((ins[0].address+4)&~3)+o[1].mem.disp
    if not (0<=lit-BASE<len(d)-4): return None
    L=struct.unpack_from('<I',d,lit-BASE)[0]
    # find the following add rX,pc
    for j in ins[1:]:
        if j.mnemonic=='add' and 'pc' in j.op_str:
            return L + j.address + 4, L, lit
    return None
if __name__=='__main__':
    for a in sys.argv[1:]:
        va=int(a,16)
        r=resolve_at(va)
        if r:
            s=cstr(r[0])
            print(f"  {va:#010x}: lit@{r[2]:#x}={r[1]:#x} -> {r[0]:#010x}  \"{s}\"")
        else:
            print(f"  {va:#010x}: (not a pc-relative string load)")
