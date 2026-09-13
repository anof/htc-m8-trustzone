#!/usr/bin/env python3
"""Extract the kernel from a dumped HTC boot image and look for the build config.

boot.img layout (verified earlier):
  0x000-0x0FF  HTC header (signature block)
  0x100        "ANDROID!" boot header (page 2048)
  0x900        kernel (zImage)
  ...          ramdisk (page aligned)

If the kernel was built with CONFIG_IKCONFIG, the .config is embedded between
IKCFG_ST / IKCFG_ED markers in the decompressed image.
"""
import struct, gzip, io, re, sys

img = open("boot.img", "rb").read()
kern_size = struct.unpack_from("<I", img, 0x100 + 8)[0]
zimage = img[0x900:0x900 + kern_size]
print(f"zImage: {len(zimage)} bytes, first8={zimage[:8].hex(' ')}")

# find the compressed payload inside the self-extracting stub
cands = []
for magic, name in ((b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ", "xz"),
                    (b"BZh", "bzip2"), (b"\x5d\x00\x00", "lzma")):
    for m in re.finditer(re.escape(magic), zimage[: 0x200000]):
        cands.append((m.start(), name))
cands.sort()
print("compressed payload candidates:", [(hex(o), n) for o, n in cands[:5]])

kernel = None
for off, name in cands:
    if name != "gzip":
        continue
    try:
        kernel = gzip.decompress(zimage[off:])
        print(f"decompressed gzip payload at {off:#x}: {len(kernel)} bytes")
        break
    except Exception as e:
        continue

if kernel is None:
    # try raw/cpio-only or uncompressed kernel
    print("no gzip payload decompressed; treating zImage as-is")
    kernel = zimage

open("kernel.bin", "wb").write(kernel)
i = kernel.find(b"IKCFG_ST")
j = kernel.find(b"IKCFG_ED")
print(f"IKCFG_ST at {i if i>=0 else 'not found'} / IKCFG_ED at {j if j>=0 else 'not found'}")
if i >= 0 and j > i:
    blob = kernel[i + 8:j]
    try:
        cfg = gzip.decompress(blob)
        open("kernel_config.txt", "wb").write(cfg)
        txt = cfg.decode("utf-8", "replace")
        print("config extracted, bytes:", len(cfg))
        for key in ("CONFIG_MODVERSIONS", "CONFIG_MODULES", "CONFIG_SMP",
                    "CONFIG_PREEMPT", "CONFIG_LOCALVERSION", "CONFIG_ARM",
                    "CONFIG_IKCONFIG", "CONFIG_MODULE_SIG"):
            for line in txt.splitlines():
                if line.startswith(key + "=") or line.startswith("# " + key + " "):
                    print("   ", line)
    except Exception as e:
        print("config gunzip failed:", e)
