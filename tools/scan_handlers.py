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
def inimg(va):
    for v,o,sz in SH:
        if v<=va<v+sz: return True
    return False
def get(va,n):
    for v,o,sz in SH:
        if v<=va<v+sz:
            return h[o+(va-v): o+(va-v)+min(n, sz-(va-v))]
    return None
def cstr(va,ml=44):
    b=get(va,ml)
    if not b: return None
    out=b''
    for c in b:
        if c==0: break
        out += bytes([c]) if 32<=c<127 else b'.'
    return out.decode()

# recover the descriptor table
rows=[]
for v,o,sz in SH:
    if not (0xfe800000<=v<=0xfe840000): continue
    for i in range(0,sz-20,4):
        vid=struct.unpack_from('<I',h,o+i)[0]
        nm=struct.unpack_from('<I',h,o+i+4)[0]
        svc=vid>>10; cmd=vid&0x3ff
        if not (1<=svc<=0xfe and cmd<=0x3ff and vid<0x40000): continue
        s=cstr(nm)
        if s and s.startswith('tzbsp'):
            fn=struct.unpack_from('<I',h,o+i+12)[0]
            fl=struct.unpack_from('<I',h,o+i+8)[0]
            ex=struct.unpack_from('<I',h,o+i+16)[0]
            rows.append((v+i,svc,cmd,s,fn,fl,ex))
rows.sort()
print(f"descriptors: {len(rows)}")
inC=[r for r in rows if inimg(r[4]&~1)]
outC=[r for r in rows if not inimg(r[4]&~1)]
print(f"handler in image: {len(inC)}   handler out of image (runtime-loaded): {len(outC)}")
print()
print("=== in-image handlers ===")
for a,svc,cmd,s,fn,fl,ex in inC:
    print(f"  {fn:#010x}  svc={svc:#04x} cmd={cmd:3d} flags={fl:#x} extra={ex}  {s}")
print()
print("=== out-of-image handlers ===")
for a,svc,cmd,s,fn,fl,ex in outC:
    print(f"  {fn:#010x}  svc={svc:#04x} cmd={cmd:3d}  {s}")
