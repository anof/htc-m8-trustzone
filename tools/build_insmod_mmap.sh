#!/bin/sh
# Build insmod_mmap for the device: ARMv7, dynamically linked against the
# phone's own bionic libc (pulled into ../androidlib) so it can just be
# pushed and run.  It open()s the .ko, mmap()s it and calls init_module(2)
# -- used instead of toybox insmod because the module has to be handed to
# the kernel as a mapped buffer.
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
  -I../androidlib -L../androidlib -lc \
  insmod_mmap.c -o insmod_mmap

"$LLVM/llvm-readelf" -h insmod_mmap | grep -E "Class|Machine|Entry"
echo "built: $HERE/insmod_mmap"
