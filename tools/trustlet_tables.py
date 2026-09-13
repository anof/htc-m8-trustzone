import struct, os, re
ORDER=['mdt','b00','b01','b02','b03','b04']
def load(name):
    p=f'trustlets/merged/{name}.img'
    return open(p,'rb').read() if os.path.exists(p) else None
def tables(data, minrun=4):
    runs=[]
    off=0; n=len(data)
    while off < n-12*minrun:
        ids=[struct.unpack_from('<I',data,off+k*12)[0] for k in range(minrun)]
        if all(0x10000<=v<=0x90000 for v in ids) and len({v>>16 for v in ids})==1 \
           and sorted(ids)==ids and len(set(ids))==len(ids):
            o=off; entries=[]
            while o < n-12:
                a,b,c=struct.unpack_from('<III',data,o)
                if a==0xffffffff or a==0: break
                entries.append((a,b,c)); o+=12
            runs.append((off,entries)); off=o
        else:
            off+=4
    return runs
for name in ('widevine','keymaster','cmnlib','dxhdcp2','hcheck','mirlink','mc_v2'):
    d=load(name)
    if not d: continue
    rs=tables(d)
    print(f"=== {name} ({len(d)} bytes) — {len(rs)} candidate table(s) ===")
    for off,ents in rs[:2]:
        print(f"   table @ {off:#x}: {len(ents)} entries, ids {hex(ents[0][0])}..{hex(ents[-1][0])}")
        for a,b,c in ents[:6]:
            print(f"      cmd={a:#09x} f2={b:#010x} desc={c:#010x}  (parm={c>>16:#x} resp={c&0xffff:#x})")
    if not rs: print("   (no table matched)")
    print()
