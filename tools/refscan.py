import struct, sys
from capstone import *

def segs(path):
    d=open(path,'rb').read(); f=struct.unpack_from('<HHIIIIIHHHHHH', d, 0x10); out=[]
    for k in range(f[9]):
        p=struct.unpack_from('<IIIIIIII', d, f[4]+k*32)
        if p[0]==1 and p[4]>0: out.append((p[2], d[p[1]:p[1]+p[4]], p[5]))
    return out

def find_literal(img, val, only_code=True):
    """find raw dword occurrences (literal pools)"""
    pat=struct.pack('<I',val); hits=[]
    for base,b,mem in img:
        if only_code and base not in (0xfc86000,0xfe806000,0xfe810000): continue
        i=0
        while True:
            j=b.find(pat,i)
            if j<0: break
            hits.append(base+j); i=j+1
    return hits

def find_movw_movt(img, val, lookahead=12):
    """find ARM movw/movt pairs building val"""
    lo=val & 0xffff; hi=(val>>16)&0xffff
    out=[]
    for base,b,mem in img:
        if base not in (0xfc86000,0xfe806000,0xfe810000): continue
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(b,base))
        for n,i in enumerate(ins):
            if i.mnemonic!='movw': continue
            ops=[o.strip() for o in i.op_str.split(',')]
            if len(ops)!=2: continue
            try: v=int(ops[1],16)
            except: continue
            if v!=lo: continue
            reg=ops[0]
            for j in ins[n+1:n+1+lookahead]:
                if j.mnemonic=='movt':
                    o2=[o.strip() for o in j.op_str.split(',')]
                    if len(o2)==2 and o2[0]==reg:
                        try: v2=int(o2[1],16)
                        except: continue
                        if v2==hi: out.append((i.address, reg, j.address))
    return out

if __name__=='__main__':
    img=segs(sys.argv[1])
    for arg in sys.argv[2:]:
        val=int(arg,16)
        lit=find_literal(img,val)
        mm=find_movw_movt(img,val)
        print(f"{val:#010x}: literal-pool x{len(lit)} {[hex(x) for x in lit[:8]]}")
        print(f"            movw/movt x{len(mm)} {[(hex(a),r,hex(c)) for a,r,c in mm[:8]]}")
