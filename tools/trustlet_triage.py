import struct
from capstone import *
d=open('wv/widevine.img','rb').read()
CODE_OFF=0x3000; CODE_SZ=0x24a10
code=d[CODE_OFF:CODE_OFF+CODE_SZ]
MEMCPY=0x21d58-CODE_OFF; MEMMOVE=0x21e38-CODE_OFF
mdA=Cs(CS_ARCH_ARM, CS_MODE_ARM); mdA.detail=True
mdT=Cs(CS_ARCH_ARM, CS_MODE_THUMB); mdT.detail=True

def callsites():
    out=[]
    for off in range(0, CODE_SZ-4, 2):
        for md,mode in ((mdA,'arm'),(mdT,'thumb')):
            if mode=='arm' and off%4: continue
            for ins in md.disasm(code[off:off+4], off):
                if ins.mnemonic in ('bl','blx') and ins.operands and ins.operands[0].type==2:
                    t=ins.operands[0].imm & 0xffffffff
                    if t in (MEMCPY,MEMMOVE): out.append((off,mode))
                break
    return sorted(set(out))

def window(addr, mode, span=64):
    """disassemble a window that ends exactly at addr"""
    md = mdA if mode=='arm' else mdT
    step = 4 if mode=='arm' else 2
    for start in range(max(0,addr-span), addr, step):
        ins=list(md.disasm(code[start:addr], start))
        if ins and ins[-1].address+ins[-1].size==addr:
            return ins
    return []

def writes_r2(ins):
    if not ins.operands: return False
    if ins.mnemonic in ('mov','movs','movw','add','adds','sub','subs','ldr','ldrh','ldrb','and','ands','orr','lsl','lsls','lsr','lsrs','adr'):
        o=ins.operands[0]
        return o.type==1 and ins.reg_name(o.reg)=='r2'
    return False

cands=[]
for addr,mode in callsites():
    ins=window(addr,mode)
    if not ins: continue
    last=None
    for k in range(len(ins)-1,-1,-1):
        if writes_r2(ins[k]): last=k; break
    if last is None: continue
    src=ins[last]
    checked=any(i.mnemonic in ('cmp','cmn','tst') and 'r2' in i.op_str for i in ins[last:])
    frommem = src.mnemonic in ('ldr','ldrh','ldrb')
    if frommem and not checked:
        cands.append((addr,mode,src.mnemonic,src.op_str))
print(f"candidate unchecked memcpy sites: {len(cands)}")
for a,m,mn,ops in cands:
    print(f"   code+{a:#07x} {m:5s}  r2 <= {mn} {ops}")
