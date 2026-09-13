#!/bin/sh
# Build dloadmod.ko for the HTC M8 3.4 kernel (same recipe as kmod/tz).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
CLANG="$LLVM/clang"
LLD=$(command -v ld.lld || echo /opt/homebrew/bin/ld.lld)

CFLAGS="--target=armv7-none-linux-gnueabi -march=armv7-a -marm -O2 \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-common \
 -fno-asynchronous-unwind-tables -fno-unwind-tables -nostdlib"

cd "$HERE"
"$CLANG" $CFLAGS -c dloadmod.c  -o dloadmod.o
"$CLANG" $CFLAGS -c dloadmeta.c -o dloadmeta.o
"$LLD" -r -o dloadmod.ko dloadmod.o dloadmeta.o

python3 - <<'PY'
import struct
p='dloadmod.ko'
d=bytearray(open(p,'rb').read())
struct.pack_into('<I', d, 0x24, 0x05000000)
open(p,'wb').write(d)
print("e_flags patched -> 0x05000000")
PY
"$LLVM/llvm-readelf" -h dloadmod.ko | grep -E "Type|Machine|Flags"
"$LLVM/llvm-readelf" -s dloadmod.ko | awk '$7=="UND" && $8!="" {print "   UND "$8}'
echo "built: $(ls -l dloadmod.ko | awk '{print $5}') bytes"
