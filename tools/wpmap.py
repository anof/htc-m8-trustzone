#!/usr/bin/env python3
"""Map which eMMC partitions the AP can actually write.
For each partition: read 16 bytes at OFF, write a pattern, read back, restore.
"""
import subprocess

BLKIO = "/data/local/tmp/blkio"
OFF = 0x1000
PAT = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
PARTS = [2, 3, 4, 5, 6, 10, 12, 24, 29, 43, 46, 48, 22, 21]


def sh(cmd):
    r = subprocess.run(["adb", "shell", f'su -c "{cmd}"'],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip() + r.stderr.strip()


def main():
    print(f"{'part':>5} {'writable':>9}  original")
    for p in PARTS:
        dev = f"/dev/block/mmcblk0p{p}"
        r = sh(f"{BLKIO} r {dev} {OFF:x} 10")
        orig = ""
        for line in r.splitlines():
            if line and all(c in "0123456789abcdef" for c in line):
                orig = line
        if not orig:
            print(f"{p:>5} {'?':>9}  ({r.splitlines()[-1] if r else 'no read'})")
            continue
        sh(f"{BLKIO} w {dev} {OFF:x} {PAT}")
        r2 = sh(f"{BLKIO} r {dev} {OFF:x} 10")
        after = ""
        for line in r2.splitlines():
            if line and all(c in "0123456789abcdef" for c in line):
                after = line
        ok = after == PAT
        print(f"{p:>5} {'YES' if ok else 'no ':>9}  {orig}")
        if ok:
            sh(f"{BLKIO} w {dev} {OFF:x} {orig}")


if __name__ == '__main__':
    main()
