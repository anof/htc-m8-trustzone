#!/usr/bin/env python3
"""Rebuild the Lineage 14.1 m8 boot image with a root adbd.

Patches default.prop inside the ramdisk (same-length edits, so the cpio
layout is untouched) and re-packs the Android boot image with updated
sizes.  Only boot.img is changed; kernel and device tree are copied
byte-for-byte.

usage: build_root_boot.py <src boot.img> <out boot.img>
"""
import gzip
import io
import struct
import sys

PAGE_ALIGN_HEADER = 0x100  # m8 boot header is followed by cmdline/extra

EDITS = [
    (b"ro.secure=1", b"ro.secure=0"),
    (b"ro.adb.secure=1", b"ro.adb.secure=0"),
]


def patch_cpio(cpio: bytes) -> tuple[bytes, int]:
    out = bytearray(cpio)
    pos = 0
    changed = 0
    while pos + 110 <= len(out) and out[pos:pos + 6] == b"070701":
        f = [int(out[pos + 6 + 8 * i:pos + 6 + 8 * (i + 1)], 16) for i in range(13)]
        filesize, namesize = f[6], f[11]
        name = bytes(out[pos + 110:pos + 110 + namesize - 1])
        hdr = (110 + namesize + 3) // 4 * 4
        data_off = pos + hdr
        if name == b"default.prop":
            data = bytes(out[data_off:data_off + filesize])
            for old, new in EDITS:
                assert len(old) == len(new)
                idx = data.find(old)
                if idx >= 0:
                    data = data[:idx] + new + data[idx + len(old):]
                    changed += 1
            out[data_off:data_off + filesize] = data
        pos = data_off + ((filesize + 3) // 4 * 4)
    return bytes(out), changed


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    img = bytearray(open(src, "rb").read())
    assert img[:8] == b"ANDROID!", "not an Android boot image"

    (kern, kaddr, rdsize, raddr, sec, saddr, tags, page, dt_size, _) = \
        struct.unpack_from("<10I", img, 8)
    assert page == 2048

    koff = page
    roff = koff + (kern + page - 1) // page * page
    soff = roff + (rdsize + page - 1) // page * page
    doff = soff + (sec + page - 1) // page * page

    kernel = bytes(img[koff:koff + kern])
    ramdisk = bytes(img[roff:roff + rdsize])
    second = bytes(img[soff:soff + sec])
    dt = bytes(img[doff:doff + dt_size])

    cpio = gzip.decompress(ramdisk)
    patched, changed = patch_cpio(cpio)
    print(f"default.prop edits applied: {changed}")
    if changed != len(EDITS):
        raise SystemExit("expected property edits not found")
    assert len(patched) == len(cpio), "cpio size changed"

    buf = io.BytesIO()
    import subprocess
    with subprocess.Popen(["gzip", "-9", "-n", "-c"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE) as p:
        new_rd, _ = p.communicate(patched)
    print(f"ramdisk {rdsize} -> {len(new_rd)} bytes")

    new = bytearray(img[:page])
    struct.pack_into("<I", new, 8 + 8, len(new_rd))  # ramdisk_size

    def pad(b: bytes) -> bytes:
        rem = len(b) % page
        return b + (b"\x00" * (page - rem) if rem else b"")

    body = pad(kernel) + pad(new_rd) + pad(second) + pad(dt)
    out = bytes(new) + body
    open(dst, "wb").write(out)
    print(f"wrote {dst} ({len(out)} bytes)")

    # sanity: re-parse
    chk = open(dst, "rb").read()
    print("re-parse magic:", chk[:8], "ramdisk_size:", struct.unpack_from("<I", chk, 16)[0])


if __name__ == "__main__":
    main()
