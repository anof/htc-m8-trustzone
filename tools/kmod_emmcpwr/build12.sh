#!/bin/sh
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
CLANG="$LLVM/clang"
LLD=$(command -v ld.lld || echo /opt/homebrew/bin/ld.lld)
CFLAGS="--target=armv7-none-linux-gnueabi -march=armv7-a -marm -O2 \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-common \
 -fno-asynchronous-unwind-tables -fno-unwind-tables -nostdlib \
 -fno-omit-frame-pointer -mno-unaligned-access"
cd "$HERE"
"$CLANG" $CFLAGS -c emmcpwr12.c -o emmcpwr12.o
"$CLANG" $CFLAGS -c emmcpwr12_meta.c -o emmcpwr12_meta.o
"$LLD" -r -o emmcpwr12.ko emmcpwr12.o emmcpwr12_meta.o
python3 - <<'PY'
import struct
p='emmcpwr12.ko'
d=bytearray(open(p,'rb').read())
struct.pack_into('<I', d, 0x24, 0x05000000)
open(p,'wb').write(d)
print(p, "e_flags patched")
PY
"$LLVM/llvm-readelf" -s emmcpwr12.ko | awk '$7=="UND" && $8!="" {print "   UND "$8}'
ls -l emmcpwr12.ko
