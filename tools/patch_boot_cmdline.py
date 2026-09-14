#!/usr/bin/env python3
"""Rewrite the kernel command line inside an Android boot image.

Why this is needed on this device: hboot appends its own ~900-byte debug
string to the kernel cmdline in a 1024-byte buffer.  If the boot image's
own cmdline is long (TWRP and Lineage ship 130-160 bytes), the buffer
overflows, hboot dies with an "hboot exception" and the image never boots.
Keeping the image cmdline at ~25-60 bytes avoids it entirely.

The cmdline field is a fixed 512-byte area at offset 0x40 of the AOSP boot
header, so the edit is same-size and the rest of the image is untouched.

usage: patch_boot_cmdline.py <in.img> <out.img> ["cmdline string"]
       (default cmdline: androidboot.hardware=qcom)
"""
import sys

CMD_OFF = 0x40
CMD_LEN = 512
DEFAULT = b"androidboot.hardware=qcom"


def main() -> None:
    src, dst = sys.argv[1], sys.argv[2]
    cmd = sys.argv[3].encode() if len(sys.argv) > 3 else DEFAULT
    if len(cmd) >= CMD_LEN:
        raise SystemExit("cmdline too long")
    img = bytearray(open(src, "rb").read())
    if img[:8] != b"ANDROID!":
        raise SystemExit("not an Android boot image (no ANDROID! magic)")
    old = bytes(img[CMD_OFF:CMD_OFF + CMD_LEN]).split(b"\x00")[0]
    img[CMD_OFF:CMD_OFF + CMD_LEN] = cmd + b"\x00" * (CMD_LEN - len(cmd))
    open(dst, "wb").write(bytes(img))
    print(f"cmdline {len(old)} -> {len(cmd)} bytes: {cmd.decode()}")
    print(f"wrote {dst} ({len(img)} bytes, size unchanged: "
          f"{len(img) == len(open(src, 'rb').read())})")


if __name__ == "__main__":
    main()
