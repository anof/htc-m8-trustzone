import struct, os, re, glob
os.makedirs('trustlets/merged', exist_ok=True)
ORDER=['mdt','b00','b01','b02','b03','b04']
def merge(name):
    parts=[]
    for s in ORDER:
        p=f'trustlets/{name}.{s}'
        if os.path.exists(p): parts.append(open(p,'rb').read())
    if not parts: return None
    data=b''.join(parts)
    open(f'trustlets/merged/{name}.img','wb').write(data)
    return data
def info(name, data):
    f=struct.unpack_from('<HHIIIIIHHHHHH', data, 0x10)
    segs=[]
    for k in range(f[9]):
        p=struct.unpack_from('<IIIIIIII', data, f[4]+k*32)
        if p[0]==1 and p[4]>0: segs.append((p[2],p[4],p[6]))
    # find the method table: run of 12-byte entries with plausible cmd ids
    best=None
    for off in range(0,len(data)-12*8,4):
        ids=[struct.unpack_from('<I',data,off+k*12)[0] for k in range(8)]
        # a method table: cmd ids share a high half and increment
        if not all(0x10000<=v<=0x90000 for v in ids): continue
        if len({v>>16 for v in ids})!=1: continue
        if sorted(ids)!=ids or len(set(ids))!=len(ids): continue
        if best is None: best=off
    cmds=[]
    if best is not None:
        o=best
        while True:
            a,b,c=struct.unpack_from('<III',data,o)
            if a==0xffffffff or a==0: break
            cmds.append((a,c)); o+=12
    vers=set()
    for m in re.finditer(rb'[ -~]{6,40}', data):
        s=m.group(0)
        if any(k in s for k in (b'widevine',b'keymaster',b'KeyMaster',b'Widevine',b'version',b'Version',b'QUALCOMM',b'QSEE',b'build')):
            vers.add(s.decode())
    return segs, best, cmds, sorted(vers)[:4]
print(f"{'trustlet':10s} {'size':>8s} {'code':>8s} {'tbl@':>8s} {'cmds':>5s}  first cmds")
for name in ('widevine','keymaster','cmnlib','dxhdcp2','hcheck','mirlink','mc_v2'):
    d=merge(name)
    if not d: continue
    segs,tbl,cmds,vers=info(name,d)
    code = segs[0][1] if segs else 0
    cids=[hex(c[0]) for c in cmds[:5]]
    tbls = hex(tbl) if tbl is not None else "-"
    print(f"{name:10s} {len(d):8d} {code:#8x} {tbls:>8s} {len(cmds):5d}  {cids}")
    if vers: print(f"           strings: {vers}")
