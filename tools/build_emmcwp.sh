#!/bin/sh
# Build emmcwp for the device: ARMv7, dynamically linked against the phone's
# own bionic libc (pulled into ./androidlib) so it can just be pushed and run.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}

"$LLVM/clang" \
  --target=armv7-none-linux-gnueabi -march=armv7-a -marm -O2 \
  -fuse-ld=lld -nostdlib -nostartfiles \
  -Wl,--hash-style=both -Wl,-e,_start \
  -Wl,--dynamic-linker=/system/bin/linker \
  -Wl,-rpath,/system/lib -Wl,-rpath,/vendor/lib \
  -Iandroidlib -Landroidlib -lc \
  emmcwp.c -o emmcwp

"$LLVM/llvm-readelf" -h emmcwp | grep -E "Class|Machine|Type|Entry"
"$LLVM/llvm-nm" -D --undefined-only emmcwp | head -20
echo "built: $HERE/emmcwp"
