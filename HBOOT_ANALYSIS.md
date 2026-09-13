# HTC One (M8) hboot 3.19.0.0000 — analysis

Deep dive into the bootloader, to look for either (a) a weakness in the unlock
token verifier, or (b) a bug in a code path reachable while the device is still
LOCKED.

## Image layout

`hboot.img`, 4 MB dump of `/dev/block/mmcblk0p11`,
sha256 `da4289df70e366b262833b7d0f5ca111edf0317c3f83bfc7dc237c5afd8fc1fe`.

Partition header at offset 0:

```
0x000c  0x0F500000        load address
0x0010  0x1FFCD8          image size (~2 MB)
0x0028  ARM branch        entry
0x002c  "3.19.0.0000"     version
0x0048  "SHIP"            build type (not an ENG build)
```

Entropy profiling: only ~1.7 MB of the 4 MB has content; everything past
`0x1B0000` is zero padding. The first ~512 KB is high-entropy (~7.0), the rest
is ordinary code and data.

## Method — the key that unlocked everything

Absolute pointer searches failed, because **hboot references strings
PC-relatively**:

```
ldr.w rX, [pc, #imm]     ; loads an *offset*
add   rX, pc             ; string = offset + (addr_of_add + 4)
```

(`add rX, pc` uses PC = address of the ADD + 4, on ARM and Thumb alike.)

Scanning for this pattern — decoding one instruction at every 2-byte offset to
avoid drift through data regions — yields **2,730 resolved string
references**. That is the xref database everything below is built from.
Tools: `tools/xref2.py`, `tools/resolve.py`, `tools/hbwalk.py`.

## The fastboot command dispatcher

At `0x0f51d730`. A `strncmp` chain against:

```
"getvar:"            (7)
"oem "               (4)
"reboot-bootloader"  (17)
"reboot"             (6)
"download:"          (9)
```

The `download:` handler (from `0x0f51d866`) does:

```
bl   get_max_download_size
sub.w r0, r0, #0x100000
cmp  r5, r0
bhi  <error>                 ; reject if size > max - 0x100000
mov  r0, r5 ; movs r1,#1
bl   malloc                  ; allocate the download buffer
```

This bounds check is **correct**. (Earlier fuzzing accepted `0x6CDCE001`; that
is simply below the real limit, not a bypass. `0xFFFFFFFF` is rejected.)

## The OEM command table

At file `0x14eb90`–`0x14ece8`: 12-byte entries `{name_ptr, 0, handler_ptr}`.
Full list recovered, including:

```
writecid              -> 0x0f515329
writeimei             -> 0x0f515269
writemeid             -> 0x0f516059
writepid              -> 0x0f515bbd
writesecureflag       -> 0x0f515b65
readsecureflag        -> 0x0f5156ad
get_identifier_token  -> 0x0f514f39
checkKeycardID        -> 0x0f514f1d
refurbish             -> (see below)
```

Note the handler pointers are Thumb addresses; the low bit must be masked
before disassembling.

## ★ The unlock gate is a hardcoded string comparison ★

This is the most significant finding. At `0x0f503590`:

```asm
0x0f503590  push  {r3, lr}
0x0f503592  bl    0xf50d99c          ; get_cid()  -> pointer to CID string
0x0f503596  movs  r2, #8
0x0f503598  ldr   r1, = "VZW__001"   ; hardcoded blocker
0x0f50359c  bl    0xf53acd0          ; strncmp(cid, "VZW__001", 8)
0x0f5035a0  rsbs.w r0, r0, #1        ; invert
0x0f5035a4  it    lo
0x0f5035a6  movlo r0, #0
0x0f5035a8  pop   {r3, pc}
```

Returns **1 ("not supported") iff the CID equals `VZW__001`**, else 0.

There is a **second, identical copy** of this predicate at `0x0f514e48`
(same `get_cid` call, same literal, arguments swapped).

`"VZW__001"` appears in the whole image as a string exactly once
(`0x0f57ef87`), and is referenced from exactly those two code sites.

Caller (`flash unlocktoken` handler, `0x0f51dccc`):

```asm
0x0f51dccc  ldr r1, = "unlocktoken"
0x0f51dcd4  bl  strcmp               ; is this the unlocktoken target?
0x0f51dcda  bne  next
0x0f51dcde  bl  0xf503590            ; the CID gate above
0x0f51dce4  cbz r0, 0xf51dcf4        ; 0 -> permitted, proceed to parse
0x0f51dce6  ldr r0, = "FAILNot support on this device!"
0x0f51dcf0  b   fail
```

So the device-side refusal to unlock is **policy implemented as `strcmp`
against a constant** — not a fuse, not a signature, not TrustZone.

### Where the CID comes from

`get_cid()` at `0x0f50d99c`:

```asm
ldr r0, [pc, #0xc]      ; offset 0x197816
add r0, pc              ; r0 = 0x0F6A51B8
ldr r0, [r0]            ; base pointer of a runtime config structure
add.w r0, r0, #0x15800
add.w r0, r0, #0x12c    ; + 0x1592C  <- CID lives here
bx  lr
```

Sibling accessors return `base + 0x704C` and `base + 0x701C`, so the structure
is a large (~90 KB) parsed configuration block built at boot.

**Open question: which partition that structure is parsed from.** The CID
exists in two places on flash:

| Location | Contents | Writable from Android? |
|---|---|---|
| `board_info` (p3) | CID at `0x14`, serial, then **32-byte integrity hashes** | **no** — writes dropped |
| `misc` (p24) | CID at `0x00`, plain, **no hash** | **yes** — measured |

If hboot builds the CID from `misc`, the gate is defeatable by editing a
writable partition. If it uses `board_info`, the hash blocks it. Tracing the
config builder (xrefs to `"HTC-BOARD-INFO!@"` at `0x0f52eb54` and
`0x0f530754`) settles this offline and is the next thing to do.

## The other CID machinery

`0x0f514e68` walks a table with **stride 12**, comparing a name and returning
the entry, defaulting to `"COMMON"`. That is the CID → region lookup whose
data sits at file `0x14e47c` (entries `Samsung`, `T-MOB010`, `VODAP001`,
`HTC__001`, `GOOGLE`, `CWS__001`, … — ~150 entries).

## Why this matters strategically

HTCdev's rejection message was **"CID Not Allowed (MID not exist in Model
Rule)"** — the headline reason is the *CID*. If that server-side rule is also
keyed on `VZW__001`, then changing the CID could satisfy **both** gates at
once: HTCdev would sign a token, and hboot's local check would pass.

That reframes the problem from "find a bootloader exploit" to "change one
16-byte string that already lives in a writable partition."

## Risk note — do not test blindly

Editing the CID in `misc` and rebooting is the obvious experiment, and it is
**not** obviously safe: if hboot cross-checks `misc` against `board_info` and
refuses to boot on mismatch, the device will not come back up, and `misc`
cannot be restored from fastboot (writing partitions needs an unlocked
bootloader). The offline trace above should be done first.
