#!/usr/bin/env python3
"""Drift-free PC-relative string xref finder for hboot.
Decode one instruction at every 2-byte offset; when it is an LDR-literal,
follow with a short window to find the matching 'add rX, pc'."""
import struct
from capstone import *
from capstone.arm import ARM_OP_MEM, ARM_REG_PC
BASE=0x0F500000
d=open('/Users/azizdaoud/m8-soff/hboot.img','rb').read()
md=Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail=True
def cstr(va,ml=64):
    off=va-BASE
    if not (0<=off<len(d)): return None
    e=d.find(b'\x00',off)
    if e<0 or e-off>ml: return None
    t=d[off:e]
    if not t or any(c<0x20 or c>0x7e for c in t): return None
    return t.decode()
out=[]
n=len(d)
for off in range(0, n-4, 2):
    ins=list(md.disasm(d[off:off+4], BASE+off))
    if not ins: continue
    i=ins[0]
    if i.mnemonic not in ('ldr','ldr.w','adr'): 
        continue
    if i.mnemonic=='adr':
        # adr rX, label  -> add rX, pc form already absolute
        continue
    o=i.operands
    if len(o)<2 or o[1].type!=ARM_OP_MEM or o[1].mem.base!=ARM_REG_PC: continue
    lit=((i.address+4)&~3)+o[1].mem.disp
    if not (0<=lit-BASE<n-4): continue
    L=struct.unpack_from('<I',d,lit-BASE)[0]
    reg=i.reg_name(o[0].reg)
    # decode a short window after this instruction
    p=off+i.size
    for _ in range(3):
        nxt=list(md.disasm(d[p:p+4], BASE+p))
        if not nxt: break
        j=nxt[0]
        if j.mnemonic=='add' and j.op_str.startswith(reg+',') and 'pc' in j.op_str:
            va=L+j.address+4
            s=cstr(va)
            if s: out.append((i.address, va, s))
            break
        p+=j.size
# dedupe
seen=set(); res=[]
for ca,va,s in out:
    k=(ca,va)
    if k in seen: continue
    seen.add(k); res.append((ca,va,s))
print(f"resolved {len(res)} PC-relative string refs")
import sys
pats=sys.argv[1:]
if pats:
    for p in pats:
        print(f"\n=== {p!r} ===")
        for ca,va,s in res:
            if p.lower() in s.lower():
                print(f"   code {ca:#010x} -> {va:#010x}  \"{s}\"")
else:
    for ca,va,s in res[:60]:
        print(f"   {ca:#010x} -> {s}")
