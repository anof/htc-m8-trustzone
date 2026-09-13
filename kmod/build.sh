#!/bin/sh
# Build a loadable module for the HTC M8 (MSM8974) 3.4 kernel using a
# generic LLVM ARM toolchain, then hand-patch the ELF to match the kernel's
# expectations (EABI5 e_flags, no hard-float marker).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
CLANG="$LLVM/clang"
LLD=$(command -v ld.lld || echo /opt/homebrew/bin/ld.lld)
OBJCOPY="$LLVM/llvm-objcopy"

CFLAGS="--target=armv7-none-linux-gnueabi -march=armv7-a -marm -O2 \
 -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-common \
 -fno-asynchronous-unwind-tables -fno-unwind-tables -nostdlib \
 -fno-omit-frame-pointer -mno-unaligned-access"

case "$1" in
  exploit) CFLAGS="$CFLAGS -DDO_EXPLOIT"; echo "*** BUILDING WITH EXPLOIT STAGE ENABLED ***" ;;
  *)       echo "*** recon-only build ***" ;;
esac

cd "$HERE"
"$CLANG" $CFLAGS -c tzmod.c  -o tzmod.o
"$CLANG" $CFLAGS -c tzmeta.c -o tzmeta.o
"$LLD" -r -o tzmod.ko tzmod.o tzmeta.o

# e_flags must be plain EABI5 (0x05000000)
python3 - <<'PY'
import struct
p='tzmod.ko'
d=bytearray(open(p,'rb').read())
struct.pack_into('<I', d, 0x24, 0x05000000)
open(p,'wb').write(d)
print("e_flags patched -> 0x05000000")
PY

"$LLVM/llvm-readelf" -h tzmod.ko | grep -E "Type|Machine|Flags"
echo "--- sections ---"
"$LLVM/llvm-readelf" -S tzmod.ko | grep -E "\.text|modinfo|versions|this_module|\.data|\.bss|\.rodata"
echo "--- undefined symbols ---"
"$LLVM/llvm-readelf" -s tzmod.ko | awk '$7=="UND" && $8!="" {print "   "$8}'
echo "built: $(ls -l tzmod.ko | awk '{print $5}') bytes"
