#!/usr/bin/env python3
"""Build an HTC "RUU zip" for flashing through hboot's RUU mode.

While the bootloader is LOCKED, `fastboot flash <partition>` is refused
("not allowed") and the only write path is:

    fastboot oem rebootRUU
    fastboot flash zip this.zip
    fastboot reboot

hboot reads android-info.txt, matches modelid/cidnum, then flashes each
image to the partition of the same name.  Notes learned the hard way:

* the download must fit max-download-size (1 GiB on this device), so keep
  zips small -- boot-only RUU zips are ~8 MB;
* entries named misc/userdata in an RUU zip are ignored;
* with SuperCID (11111111) the cidnum check passes for any value.

usage: build_ruu_zip.py <out.zip> <modelid> <cidnum> <mainver> <img> [<img>...]
       image files are stored under their own basename, so name them after
       the partition they belong to (boot.img, recovery.img, ...).
"""
import os
import sys
import zipfile

ANDROID_INFO = """modelid: {modelid}
cidnum: {cidnum}
mainver: {mainver}
btype:1
aareport:1
"""


def main() -> None:
    out, modelid, cidnum, mainver = sys.argv[1:5]
    images = sys.argv[5:]
    if not images:
        raise SystemExit("no images given")
    info = ANDROID_INFO.format(modelid=modelid, cidnum=cidnum, mainver=mainver)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("android-info.txt", info)
        total = len(info)
        for img in images:
            name = os.path.basename(img)
            z.write(img, name)
            size = os.path.getsize(img)
            total += size
            print(f"  + {name} ({size} bytes)")
    print(f"wrote {out} ({os.path.getsize(out)} bytes on disk)")
    if os.path.getsize(out) > 1024 ** 3:
        print("WARNING: larger than 1 GiB -- hboot will refuse the download")


if __name__ == "__main__":
    main()
