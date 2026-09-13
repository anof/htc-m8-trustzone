#!/usr/bin/env python3
"""patch_sec.py - build a patched copy of the S-OFF flag sector.

Reads /tmp/sec.bin (raw LBA 2148), zeroes the first dword (S-ON -> S-OFF)
and writes /tmp/sec_patched.bin plus /tmp/sec_hex.txt (hex for mmcrw w).
"""
import struct

d = bytearray(open("/tmp/sec.bin", "rb").read())
print("current flag:", hex(struct.unpack_from("<I", d, 0)[0]))
d[0:4] = struct.pack("<I", 0)
open("/tmp/sec_patched.bin", "wb").write(d)
open("/tmp/sec_hex.txt", "w").write(d.hex())
print("patched flag:", hex(struct.unpack_from("<I", d, 0)[0]))
