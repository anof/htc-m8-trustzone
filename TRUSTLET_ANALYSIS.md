# Trustlets on the HTC One (M8) — reconnaissance

## Correction to an earlier version of this file

A first pass used the merged `widevine.img` at file offset `0x3000` as the code
segment. That is wrong: the `.bXX` parts concatenate after the `.mdt`, so the
real code segment (`widevine.b02`) begins at merged offset **`0x34b8`**, not
`0x3000`. Every address derived from the merged file was therefore offset by
**`0x4b8`**. The analysis itself was sound (it operated on the correct bytes
within its own window), but the reported code-vaddr offsets were wrong.
Corrected values: **`memcpy` = `0x1e8a0`**, **`memmove` = `0x1e980`**.

Merge order for `.mdt` + `.bXX` is `mdt, b00, b01, b02, b03`, verified
byte-exact against the known-good widevine image. `.b02` is the code segment
and maps to vaddr 0.

## Inventory

Seven trustlet packages ship on this device:

| Trustlet | Merged size | Code size | Location on device | Notes |
|---|---|---|---|---|
| `widevine` | 164432 | `0x24a10` | `/system/etc/firmware` | method table at `0x27f14`, 38 cmds `0x61001`–`0x61026` + `0x20003` |
| `keymaster` | 31772 | `0x4694` | `/system/vendor/firmware` | |
| `cmnlib` | 122808 | `0x199c4` | `/system/etc/firmware` | Qualcomm shared library |
| `dxhdcp2` | 130748 | `0x1c954` | `/system/etc/firmware` | HDCP 2.x |
| `hcheck` | 32660 | `0x4a6c` | `/system/etc/firmware` | **HTC-specific** |
| `mirlink` | 31776 | `0x4610` | `/system/etc/firmware` | Miracast |
| `mc_v2` | 172740 | `0x2a000` | `/system/etc/firmware` | **Trustonic MobiCore** — a separate TEE |

Only `widevine` exposes a method table in the 12-byte `{cmd_id, 0,
(parm_size<<16)|resp_size}` form. The others either use a different table
layout or are library-style components with no outward command surface
(`cmnlib` in particular). Note that `mc_v2` is not a Qualcomm QSEE trustlet at
all — it is Trustonic's MobiCore, an entirely separate TEE implementation that
coexists on this device.

`hcheck` is the most interesting for our purpose: it is HTC-added, and its
strings reference "HTC SFS CFG", "HTC SFS key" and "CPRM key rebuild", i.e.
HTC's secure file system and key-rebuild logic.

## Widevine image structure

The trustlet is the one piece of secure-world code we can actually read: it is
signed, but it sits on disk in `/firmware`, and it runs in the secure world
reachable from the normal world through `/dev/qseecom`. Both public Widevine
exploits (CVE-2015-6639, CVE-2016-2431) are of this class, so it is the
natural next avenue after the SCM handler audit came back clean.

## Image structure

`widevine.img` (164,432 bytes) is a single trustlet image:

| Segment | File offset | Vaddr | Size | Flags |
|---|---|---|---|---|
| code (`.b02`) | `0x34b8` | `0` | `0x24a10` | RX |
| data | `0x28fcc` | `0x25000` | `0x388` (memsz `0x17d28`) | RW |

It is **not encrypted** — 6.98 bits/byte entropy and the opening bytes are
`0xFF` padding, but the body is genuine mixed **ARM and Thumb** code. The
ARM/Thumb mixing is the central difficulty for automated analysis.

`p_type = PT_NULL` header at `0x1000` / vaddr `0x3d000` is the signature
segment.

## Command table

Recovered at file `0x27f14` (in the gap between the code and data segments),
**38 entries of 12 bytes**, `{cmd_id, 0, descriptor}` where the descriptor
reads as `(parm_size << 16) | resp_size`:

```
cmd=0x61001  parm=8      resp=4
cmd=0x61002  parm=8      resp=4
cmd=0x61003  parm=0xc    resp=4
cmd=0x61004  parm=8      resp=8
cmd=0x61005  parm=8      resp=0xa010
cmd=0x61006  parm=0xc    resp=8
cmd=0x61007  parm=0x2c   resp=0xa010
cmd=0x61008  parm=8      resp=0xb61d
cmd=0x61009  parm=8      resp=0xd234
cmd=0x6100a  parm=8      resp=0xa00c
cmd=0x6100b  parm=8      resp=0x1040
cmd=0x6100c  parm=0x500c resp=0xa00c
cmd=0x6100d  parm=8      resp=0x5008
...          (through 0x61026)
cmd=0x20003
```

The large response sizes (`0xa010`, `0xb61d`, `0xd234`) are the interesting
ones — they are the buffer sizes the trustlet expects the caller to provide,
and therefore the sizes it will copy into.

**Confirmed: there is no `0x5000x` PRDiag family**, which is why
CVE-2015-6639 and CVE-2016-2431 cannot be used here. `PRDiagMaintenanceHandler`
is `0x50002`.

## Memory primitives

Found by byte-pattern search for the standard ARM memcpy prologue
(`cmp r2,#3` / `ands ip,r0,#3`), then expressed as code offsets:

| Code offset | Function |
|---|---|
| `0x1e8a0` | `memcpy` (1718 bytes; `size_t arg3 @ r2`) |
| `0x1e980` | `memmove` (backward-copy variant) |

137 call sites into `memcpy` were located and mapped to their call sites by
address.

## Where this stopped

Resolving those call sites requires correct ARM/Thumb region boundaries and
function boundaries. Both automated attempts fail on this blob:

* Linear disassembly (either mode, or both) drifts at every ARM/Thumb switch
  and at every inlined string constant — the trustlet interleaves rodata
  inside functions, so a backward window can land in ASCII.
* rizin's recursive analysis (`aaa`, `anal.armthumb=true`) merges unrelated
  code into single "functions" of >120 KB, because without entry-point hints
  it follows bad paths across ISA boundaries.

A first-pass heuristic that flagged "length loaded from memory with no
comparison before the memcpy" produced 9 candidates, but inspection showed at
least one was a misalignment artifact (the window had walked into a string
literal). **None of the 9 has been confirmed as a real bug.**

## What a real audit needs

1. Establish the ARM/Thumb entry points — e.g. by seeding the analyser with
   the 137 known memcpy call sites and walking outward, rather than from
   offset 0.
2. Recover function boundaries from those seeds.
3. Trace, for each `memcpy`, whether `r2` derives from the request buffer
   (attacker controlled) and whether any check bounds it first.
4. Prioritise the large-response commands listed above.

That is a genuine multi-day reverse-engineering task, not a scripting
exercise. It is recorded here so it can be picked up rather than rediscovered.
