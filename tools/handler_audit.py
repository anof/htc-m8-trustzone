import struct
from capstone import *
h=open('htc_tz.bin','rb').read()
def segs(d):
    f=struct.unpack_from('<HHIIIIIHHHHHH',d,0x10); s=[]
    for k in range(f[9]):
        p=struct.unpack_from('<IIIIIIII',d,f[4]+k*32)
        if p[0]==1 and p[4]>0: s.append((p[2],p[1],p[4]))
    return s
SH=segs(h)
def get(va,n):
    for v,o,sz in SH:
        if v<=va<v+sz: return h[o+(va-v): o+(va-v)+min(n, sz-(va-v))]
    return None
def inimg(va): return any(v<=va<v+sz for v,o,sz in SH)
def cstr(va,ml=44):
    b=get(va,ml)
    if not b: return None
    out=b''
    for c in b:
        if c==0: break
        out += bytes([c]) if 32<=c<127 else b'.'
    return out.decode()
rows=[]
for v,o,sz in SH:
    if not (0xfe800000<=v<=0xfe840000): continue
    for i in range(0,sz-20,4):
        vid=struct.unpack_from('<I',h,o+i)[0]; nm=struct.unpack_from('<I',h,o+i+4)[0]
        svc=vid>>10; cmd=vid&0x3ff
        if not (1<=svc<=0xfe and cmd<=0x3ff and vid<0x40000): continue
        s=cstr(nm)
        if s and s.startswith('tzbsp'):
            rows.append((svc,cmd,s,struct.unpack_from('<I',h,o+i+12)[0]))
rows.sort()
COPY={0xfe8199f4:'memcpy',0xfe819970:'memcpy2',0xfe819df4:'memmove',0xfe819918:'memset'}
VALIDATORS={0xfe810784,0xfe81307c,0xfe848b92,0xfe812720,0xfe816506}
TABLECHK=0xfe812720      # walks the {idx,count,start,end} bounds table
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB); md.detail=True
print(f"{'handler':36s} {'copy?':8s} {'validated?':10s}")
print("-"*60)
for svc,cmd,name,fn in rows:
    e=fn&~1
    if not inimg(e): continue
    blob=get(e,0x300)
    if not blob: continue
    calls=[]
    for ins in md.disasm(blob,e):
        if ins.mnemonic in ('bl','blx') and ins.operands and ins.operands[0].type==2:
            calls.append(ins.operands[0].imm & 0xffffffff)
    cp=[COPY[c] for c in calls if c in COPY]
    val = "yes" if any(v in calls for v in VALIDATORS) else "NO"
    if cp:
        print(f"{name:36s} {','.join(sorted(set(cp))):8s} {val:10s}")
