# The S-OFF flag — located, decoded, and why the AP cannot write it

Date: 2026-09-12 (evening session). Device: HTC One M8 Verizon
`HT45FSF02406`, hboot 3.19.0.0000, S-ON, CID `VZW__001`, Android 5.0.1,
firmware 4.17.605.17, temp root via KingRoot.

This file records a set of results that finally close the loop on *where*
S-ON/S-OFF is stored and what would have to be written to flip it. Every
claim below is either read straight out of the hboot/kernel disassembly or
measured on the device.

---

## 1. Where S-OFF actually lives

**`pg1fs` partition (mmcblk0p2), file `security`, first dword.**

The `pg1fs` filesystem is a simple slot format. Its first four 0x400-byte
slots name the files, and the file payloads live further in:

| slot | name (as stored) | size | payload offset |
|------|------------------|------|----------------|
| 1 | `security`  | 0x1000 | 0x8400 |
| 2 | `simlock`   | 0x1800 | 0x9400 |
| 3 | `simunlock` | 0x1000 | 0xac00 |
| 4 | `sec_setting` | 0x400 | (empty) |

hboot prepends `pg1fs_` when it looks a file up, which is why the strings
`pg1fs_security` etc. exist in the image but not in the filesystem dump.

On this device the `security` payload at partition offset **0x8400** reads:

```
03000000 00000000 01000000 00000000 ...
```

`oem readsecureflag` prints `secure_flag: 3`, i.e. the first dword *is* the
secure flag, and 3 = S-ON.

### Value semantics (from disassembly)

`f50e7a8()` is the single predicate that decides S-ON vs S-OFF everywhere
in hboot (including the " S-ON"/" S-OFF" string selection at `0x0f52f0ec`):

```
f50e7a8:
    bl  f53b5f8          ; = (read_secure_flag() > 1) ? 1 : 0
    cbnz r0, ret1
    bl  f50d64c          ; config item #7
    ubfx r0, r0, #5, #1  ; bit 5
    bx  lr
ret1: movs r0, #1
```

* `read_secure_flag()` (`f5318dc`) returns the **first dword of the
  `pg1fs_security` file**, or -1 if the block was never loaded.
* Therefore **flag > 1 ⇒ S-ON, flag ≤ 1 ⇒ S-OFF.**
  (0 is the canonical S-OFF value; 3 is what a retail S-ON device carries.)
* The second term is only consulted when the flag is already ≤ 1, i.e. it
  is an extra "force" bit, not the main switch.

### The write path in hboot

`f531898(value)` is the only writer of that dword:

```
if (value > 3) return -1;
buf = *(0x0F6A3A7C);          ; pg1fs_security buffer loaded at boot
if (!buf) return -1;
*(u32 *)buf = value;          ; <-- S-OFF flag
f504ee4("pg1fs_security", 0, buf, 0x1000);   ; write file back
```

and it is reached only from the `oem writesecureflag` handler
(`0x0f515290`):

```
value = atoi(argv[1]);
if (f50e7a8()) {                     ; currently S-ON
    if (value > 1) {
        if (check_partition_signatures()) -> "partitions siganture failed"
    }
}
if (f50e7a8()) {                     ; currently S-ON
    if (f5030b8(0x7b))               -> abort
    f566ed4(&b, &d, &d2, 1);         ; keycard / JavaCard query
    if (fail || b != 0)              -> "Permission denied, value %d"
}
f531898(value);
```

Live confirmation on this device:

```
fastboot oem writesecureflag 0
  (bootloader) [JAVACARD_ERR] SD/USBDISK Init error
  (bootloader) writesecureflag: Permission denied, value 1
fastboot oem checkKeycardID
  (bootloader) Keycard ID: -1
```

The gate is a physical **HTC service keycard** (a JavaCard presented as an
SD card or USB disk). With no keycard the whole command is refused, for
every value.

---

## 2. Why the flag cannot simply be edited from Android

Measured with a freestanding `pwrite`/`pread` tool (`blkio`) and, separately,
with **raw eMMC CMD24 writes** issued through `MMC_IOC_CMD` (bypassing the
block layer, the page cache and the filesystem entirely):

```
blkio w /dev/block/mmcblk0p2 0x8600 aa bb ...   -> pwrite rc=16, no error
blkio r /dev/block/mmcblk0p2 0x8600 10          -> 00 00 ... (unchanged)
mmcrw w /dev/block/mmcblk0 0x865 aa bb ...      -> "write accepted"
mmcrw r /dev/block/mmcblk0 0x865 1              -> 00 00 ... (unchanged)
```

The same tools write `misc` (p24), `pdata` (p29), `cache` (p48), `radio`
(p20) and others without any trouble, so the tools are correct — the
drop is specific to certain LBA ranges.

### Write-protection map (measured, at partition offset 0x1000)

| partition | writable from AP |
|---|---|
| p1..p13 (sbl1, **pg1fs**, **board_info**, reserve_1, mfg, **pg2fs**, sbl1_update, rpm, tz, sdi, hboot, sp1, wifi) | **no** |
| p14..p20, p22..p43 (ddr, dsps, adsp, wcnss, radio_config, fsg, radio, tool_diag?, custdata, reserve_2, **misc**, …) | yes (p21 tool_diag: no) |
| p44 boot, p45 recovery, p46 reserve_3, p47 system | **no** |
| p48 cache, p49 userdata | yes |

(p21 = `tool_diag` is blocked even though its neighbours are not.)

The protected partitions are exactly the ones hboot re-arms on every boot
through `msm_mpu_emmc_protect()` (see below), which is why a raw write is
accepted by the card interface and then silently discarded.

---

## 3. The mechanism: `msm_mpu_emmc_protect` and the ATS bypass

hboot strings:

```
msm_mpu_emmc_protect: set write protection fail (from mfg to reserve_1)
msm_mpu_emmc_protect: set write protection fail (from reserve_2 to modem)
msm_mpu_emmc_protect: set write protection fail (from reserve_2 to recovery)
msm_mpu_emmc_protect: set write protection fail (from reserve_2 to system)
Disable eMMC write protection due to get ats debug flag
```

Each region call looks like:

```
0f56aa44  bl f52fdf8           ; security[0x400]  == "ATS debug flag"
0f56aa48  cbz r0, do_protect
0f56aa4a  bl f53031c           ; atsdebug[0xc]    == "diswpflag"
0f56aa4e  cbz r0, do_protect
0f56aa50  movs r0, #0
0f56aa52  bl f530334           ; clear diswpflag and save its file
0f56aa56  print "Disable eMMC write protection due to get ats debug flag"
0f56aa5e  b skip
do_protect:
0f56aa7a  bl f504a30           ; partition_write_prot_mmc(start, end, 1)
```

So the protection is skipped for one boot when **both**

* `security[0x400]` (in the **pg1fs** `security` file), and
* `atsdebug_info[0xc]` (a 0x400-byte file `pg2fs_atsdebug_info` in **pg2fs**)

are non-zero.

Both files live in partitions the AP cannot write, and both are provisioned
by HTC's signed ATS flow:

* `oem ats <value>` only sets a **RAM** flag (`Set usb ats = %d`,
  `f5034cc`), used by the USB/fastboot code paths; it does not persist.
* The persistent flag is programmed from a signed blob (the "ISML" magic
  path at `0x0f5304f2`, which calls the crypto dispatcher before storing
  `security[0x400]`) or from `atsdeb.txt` ("Reading atsdeb.txt [%lu]Bytes").
* `oem clear_atsdebug` / `read_atsdebug` only clear/read this state.

Live test: after `fastboot oem ats 1` the bootloader prints
`Set usb ats = 1` but `read_atsdebug` still reports
`ATS debug flag 0, time 0 s, reboot 0 / disverflag = 0, diswpflag = 0`,
and a raw write to pg1fs after booting Android with that flag set is still
dropped. So the `ats` command alone does not disable the write protection.

---

## 4. `fastboot flash` is not the shortcut either

On this LOCKED, S-ON device every flash target is *reachable* — the
bootloader downloads the payload and then verifies it:

```
fastboot flash recovery recovery-twrp-3.7.0_9-0-m8.img
  Sending 'recovery' (16788 KB)   OKAY
  Writing 'recovery'  (bootloader) signature checking...
  FAILED (remote: 'signature verify fail')

fastboot flash misc misc.img
  Sending 'misc' (1024 KB)        OKAY
  Writing 'misc'    (bootloader) signature checking...
  FAILED (remote: 'signature verify fail')
```

The verification is `check_boot_image_signature()` (`0x0f51423a`) which
calls the crypto dispatcher at `0xf5413b0`, plus the TZ range guard
("Access denied. %X~%X is protected by TZ."). There is no per-partition
exemption: even `misc` is signature-checked.

---

## 5. What is left

1. **A bug in hboot's flash-image verification or header parser.**
   The flash path is reachable while locked, downloads attacker-controlled
   data and parses it ("MAGIC word", "shift signature_size for header
   checking", "Boot/Recovery signature checking..."). This is the only
   remaining *reachable attacker-controlled parser* that was found.
2. **A bug in the ATS provisioning path** (`atsdeb.txt` / the USB ATS
   service blob). It is signed, and the transport is HTC's own protocol,
   but it is parsed by the bootloader.
3. **A TrustZone bug** — the earlier sessions measured that HTC's TZ rejects
   every secure target address for the published MSM8974 SCM primitives, so
   this needs a different TZ bug.

The keycard/JavaCard gate and the eMMC/MPU write protection are not
software-defeatable with what is reachable today.

---

## 7. `fastboot flash` component targets (found, not yet exploited)

The flash-target dispatcher (`0x0f51c960`-`0x0f51ca40`) accepts HTC's
*component* targets in addition to partition names:

| target | handler |
|---|---|
| `zimage`   | `fb_flash_zimage` (`0x0f51ba40`) |
| `rzimage`  | restore zImage |
| `ramdisk`  | rebuild the boot image with a new ramdisk |
| `rramdisk` | restore ramdisk |
| `nbh`, `diagnbh` | full-image targets |

`fb_flash_zimage` reads the *existing* boot image header from the partition,
checks an 8-byte magic, and on mismatch logs
"Cannot find MAGIC word! Skip signature and try again..." and re-reads at
offset 0x100 before rebuilding the image with the supplied zImage/ramdisk.
That "skip signature" branch is the most interesting remaining lead: it
takes attacker-supplied data and (per its name) drops the certificate step.

### Measured caveats (important before trying it)

* A failed `fastboot flash` does **not** damage the target: after three
  failed attempts (`recovery` twice with TWRP, `recovery` with the stock
  dump, `misc` with the stock dump, all `signature verify fail`), the live
  recovery partition still byte-matches the stock dump at LBA 0x108000.
  hboot verifies before writing.
* The stock partition dump itself **fails** the flash signature check
  (`fastboot flash recovery recovery.img` -> `signature verify fail`).
  So the verifier wants HTC's signed *container*, not a raw partition
  image — and there is no fastboot-based restore path for boot/recovery.

## 8. Where the lock state is *not*

* The unlock-token success path (`0x0f51de0c`) only responds `OKAY` and
  calls one function (`0x0f53b698`) which lives in the eMMC-protection
  code and only reconfigures power rails / protection, i.e. hboot does not
  write a "now unlocked" byte from that path in a way that was locatable.
* `*** UNLOCKED ***` / `*** LOCKED ***` / `*** RELOCKED ***` are selected
  through the `f5030b8(id)` state-query API, and the "HW Security" bit that
  gates several of these comes from a hardware register read of
  `0xFC4B83F8` (QFPROM range) — i.e. fuse-backed, not writable storage.
* The kernel command line hboot generates for this device:
  `... androidboot.lb=0 uif= ... td.sf=1 ... un.ofs=696 qf.st=1 ...`
  (`lb` = lock bit, `td.sf` = tamper flag), and note `ats=1` appears there
  after `fastboot oem ats 1`, so that flag does reach the kernel — but it
  still did not disable the eMMC write protection.

---

## 9. The most promising route found so far: rebuild boot/recovery in place

`fb_flash_zimage` (`0x0f51ba40`) is **not** a plain flash. Traced end to end:

```
read 0x260-byte boot header from the partition named by the caller
  ("boot" for target `zimage`, "recovery" for target `rzimage`)
if (strncmp(header+0, MAGIC, 8) != 0) {
        print("Cannot find MAGIC word! Skip signature and try again...")
        re-read from offset 0x100            ; raw zImage layout
}
read old zImage / ramdisk / dt from the partition
allocate a fresh image buffer
memcpy header; memcpy supplied zImage; memcpy ramdisk; memcpy dt
partition_write(buffer)                       ; <- writes it back
print("Reproduce [%s] image with new zimage / ramdisk / dt ...")
```

There is **no signature verification of the supplied components anywhere in
this function** — the whole point is that HTC's OTA path rebuilds an
existing signed image around new components. The fastboot side that reaches
it is the flash-target dispatcher at `0x0f51c9c8`:

| fastboot target | partition it rebuilds |
|---|---|
| `zimage`  | `boot` |
| `rzimage` | `recovery` |
| `ramdisk` / `rramdisk` | boot / recovery ramdisk |

### Why this is the plan

Recovery is the safe place to try it: if the rebuilt image is rejected at
boot, Android still boots normally (the boot partition is untouched) and the
image can be rebuilt again the same way. The end state that matters is
TWRP running on a LOCKED, S-ON device — and once TWRP is up, LineageOS is
installable (TWRP carries its own kernel, so the stock kernel's /system
write protection no longer applies).

Steps to verify next, in order:

1. Extract the stock zImage/ramdisk from `recovery.img` (boot image header
   at 0x100, page-aligned sections).
2. `fastboot flash rzimage <stock zImage>` — if this succeeds with no
   `signature verify fail`, the primitive is real and is also its own
   restore path (rebuild with the original components).
3. Only then: rebuild recovery with TWRP's kernel + ramdisk and boot it.

### Measured result of step 2 (negative)

```
fastboot flash rzimage stock_zimage.bin      # stock zImage extracted from recovery.img @0x900
  Warning: skip copying rzimage image avb footer (rzimage partition size: 0, ...)
  Sending 'rzimage' (6365 KB)   OKAY
  Writing 'rzimage'  (bootloader) signature checking...
  FAILED (remote: 'signature verify fail')
```

So plain `fastboot flash zimage|rzimage|ramdisk` does **not** reach the
`fb_flash_zimage` rebuild path on a LOCKED device — it is first handled by
the generic flash flow, which signature-checks the payload. The rebuild
dispatcher (`0x0f51c858`) is reached from a different branch
(`0x0f51e67a`) that is itself gated by `f5030b8(3)` and by
`0xf528648`/`0xf507ae0` checks.

Recovery partition verified intact afterwards (byte-match against the stock
dump at LBA 0x108000), so this test was non-destructive.

---

## 10. How the flash chain is ordered (and the new lead)

Traced the flash-target chain (`0x0f51e460`-`0x0f51e710`). Targets are
compared in this order and each has its own branch:

```
sbl1 sbl2 sbl3 rpm tz hboot        (bootloader components)
nbh diagnbh  zip diagzip
boot recovery system zip
signature                          (separate: 256-byte blob upload)
```

* `boot`/`recovery`/`system` call `f528648(payload,len,out)` — an image
  signature verification — before anything is written.
* `zip`/`diagzip` strip the first 0x100 bytes (signature block), call
  `f525fe2(data+0x100, len-0x100, 0, ctx)`, and on success print
  **"INFOadopting the signature contained in this image..."**.
* Anything *not* in that list falls through to
  `f528648(verify)` -> `0xf51c858` (the zimage/rzimage/ramdisk/nbh
  dispatcher). That is why `flash rzimage` returned
  `signature verify fail`: the verify happens first.
* `fastboot flash signature <256-byte blob>` is a real target: it copies a
  256-byte signature into a global (`FAILsignature not 256 bytes long`
  otherwise). Combined with "adopting the signature contained in this
  image", this is how HTC's tool supplies signatures separately from the
  image.

### The RUU/ZIP update engine (best remaining attack surface)

Strings show a full ZIP update engine with its own parser and zlib:

```
----IMG.nbh / ----IMG.zip / ----DIAG.zip / --------.zip   ("----" = MID)
update.zip
Parsing...[SD ZIP] / Parsing...[downloaded ZIP]
ZIP Header Checking...  ZIP Info Parsing...  [SD_UPDATE_ERR] No image found in ZIP[%s]
[ZIP_ERR] inflate fail, zerr=%d, total_out=%lu
--preload_content=/sdcard/update.zip
```

A "downloaded ZIP" path exists (RUU mode: `fastboot oem rebootRUU` then
`fastboot flash zip <file>`), i.e. hboot parses attacker-supplied ZIP data.
Next step: determine whether the ZIP **header/directory/zlib parsing**
happens before the signature verification (the log order
`ZIP Header Checking...` -> `ZIP Info Parsing...` -> signature suggests it
does). If it does, the ZIP parser is a reachable, fuzzable memory-safety
surface inside hboot — the same class of bug the Tegra-era "torpedo"
exploit used to patch hboot images.

### Confirmed: the ZIP container is parsed structurally, with no signature check

`f525fe2(ptr,len,flag,&out)` allocates a 0x28-byte context and calls
`f527cd8`, which is a plain **unzip-style structural parser**:

```
scan backwards from the end of the buffer for a 'P' byte,
  read32 -> compare with 0x06054b50   (ZIP EOCD signature "PK\5\6")
parse EOCD fields (disk nos, entry counts, cd size/offset) into ctx+8..ctx+0x1c
  ctx+0x1c = first central-directory entry pointer
validate ctx+0x18 (comment length) and bounds (entry+0x15 < len)
then walk central-directory entries: read32 -> compare with 0x02014b50
  ("PK\1\2"), read name/extra/comment lengths, etc.
```

There is **no crypto anywhere in it** — no call into the RSA/SHA dispatchers
(`f528670`/`f528682`/`f5413a0` family) in either `f525fe2` or `f527cd8`.
The signature block of an HTC container is only *copied* ("adopting the
signature contained in this image...").

So on the update path the sequence is:

```
print "ZIP Header Checking..."
f525fe2(buf,len,...)            <- pure structure parse, no verification
  if parse OK -> "ZIP Info Parsing..." -> f509f8c(ctx) -> f50b278(ctx,len,1)  <- apply
  if parse fails -> if (S-OFF) retry at buf+0x100 (raw ZIP), else fail
```

Where the per-image signature check (if any) happens is inside the apply
path `f50b278` — that is the next thing to read, and it is the most
promising place yet for a reachable, unauthenticated hboot write path.

### The apply path starts with metadata checks, not signature checks

`f50b278(ctx,len,flag)` (the RUU/ZIP apply) begins with:

```
check model ID    ("Checking Model ID..." / "INFOchecking model ID...")
check custom ID   ("Checking Custom ID...")
                  -> "INFO Disable Main and hboot version checking for ATS debug"
check main ver    ("Checking Main Version...")
check hboot ver   ("Checking Hboot Version...")
                  -> "INFObypassing hboot version check on dev. device..."
   ... and later: "hboot"   <- the ZIP engine knows how to flash hboot itself
```

These are **metadata checks** (MID / CID / version strings read from the
package), not cryptography, and the ZIP container itself was already parsed
without any crypto. So the working hypothesis for the next session is:

> A hand-built HTC-style ZIP whose metadata claims the right MID/CID and a
> high version may be accepted far enough to reach the per-image flashing
> code — where the only remaining question is whether each image is
> signature-checked before it is written.

Test vehicle: `fastboot oem rebootRUU` (RUU mode) then
`fastboot flash zip <crafted.zip>`, or the `misc` BCB command
`update-zip` if the SD/download source can be pointed at our data.

### Exact pointers for resuming this trace

| address | role |
|---|---|
| `0x0f50b278` | RUU/ZIP **apply**: model-ID, CID, main/hboot version checks, then per-partition flush |
| `0x0f509f8c` | **"ZIP Info Parsing..."**: walks the ZIP, unzips and parses the metadata entry (`f509588`, `f509bfc`) |
| `0x0f525fe2` | ZIP **container parse** wrapper (no crypto) |
| `0x0f527cd8` | unzip-style EOCD + central-directory parser (magics `0x06054b50`, `0x02014b50`) |
| `0x0f5264c0` | per-entry unzip helper used by the apply path |
| `0x0f508038`, `0x0f507d4c` | "flush"/write helpers called after `image[hboot] unzipping for pre-update check` |
| `0x0f509f10` | find entry by name in the ZIP (used to locate `hboot`) |
| `0x0f509f8c`-region strings | `INFOstart image[hboot] unzipping for pre-update check...`, `INFOimage[hboot] Platform check fail!`, `INFOstart image[hboot] flushing...`, `Update is in progress...`, `Do not power off the device!` |

The remaining question is narrow and testable: **do `0x0f5264c0` /
`0x0f508038` / `0x0f507d4c` verify a signature for each entry, or does the
path rely only on the metadata checks and the in-image "platform check"?**
If it is the latter, a crafted ZIP with correct MID/CID/version metadata is
a direct flashing primitive on a LOCKED device — the first such primitive
found in this whole investigation.

Test discipline for that experiment: use a non-critical target first
(`userdata`, `cache`, or `recovery`), watch the bootloader log output for
the `Checking ...` lines, and never put `hboot`, `sbl1/sbl2/sbl3`, `tz` or
`rpm` in a test package.

### Where the verifiers are (and are not) called

Call-graph sweep of the whole image for the crypto entry points:

| verifier | direct call sites |
|---|---|
| `0x0f528648` (image verify: 0x100-byte sig block + body) | `0x0f506d90`, `0x0f507b44`, `0x0f51e062`, `0x0f51e610` |
| `0x0f528682` (RSA verify, e=65537) | `0x0f508796`, `0x0f51de06` (unlock token), `0x0f566b96`, `0x0f566bc4` |
| `0x0f507b20` (wraps `f528648`) | **none** — reached only indirectly |
| `0x0f508796` (wraps `f528670`/`f528682`) | **none** — reached only indirectly |

The apply path's *write* primitive (`f507be0`, 8 call sites incl.
`0x0f50b704` inside the RUU apply) does **no** verification itself, and the
apply path's own calls (`f508038`, `f507d4c`) are unverified DDR/partition
writes with progress prints. The two verifiers that exist in the
`0x0f507xxx`-`0x0f508xxx` range have no direct callers, i.e. hboot reaches
them through a function-pointer/table dispatch that has not been located
yet.

Next concrete step: find that indirect dispatch (search the `.data`/`.bss`
pointer arrays for `0x0f507b21` / `0x0f508797` — Thumb bit set) and see
whether the RUU per-image flush goes through it. If it does not, the crafted
ZIP route is a live unauthenticated flashing primitive.

### Follow-up: those wrappers are dead code, and the RUU check is an ID compare

* No code in the image materialises `0x0f507b20` / `0x0f508796` (checked
  literal pointers, `ldr+add pc`, `bl`, `blx`, and plain branches) — they are
  unreferenced in this build. Effective (live) crypto verification call
  sites in the whole image are only:
  `0x0f506d90`, `0x0f51e062`, `0x0f51e610` (fastboot flash of
  boot/recovery/system via `f528648`), `0x0f514276` (TZ SMC verify used by
  the boot-time boot/recovery check), `0x0f51de06` (unlock token RSA), and
  `0x0f566b96`/`0x0f566bc4`.
* The RUU apply path's "pre-update check" for `image[hboot]`
  (`0x0f50b5ca` -> `f508038` -> `f507c64`) is a **dword-list ID compare**
  (walk a zero-terminated list, compare against expected IDs, print
  `INFO...... Successful/Failed`), not a signature check.

So the working hypothesis is now strong: **the RUU/ZIP update path contains
no cryptographic image verification — it relies on metadata (model ID, CID,
version) and on ID lists inside the images, both of which are attacker
controlled in a hand-built package.** The next step is therefore empirical:
build a minimal HTC-style ZIP and run it through RUU mode
(`fastboot oem rebootRUU` -> `fastboot flash zip <file>`) with a
non-critical target only, and watch how far it gets.

### Measured: the RUU ZIP path is signature-gated at the door (hypothesis killed)

Built a clean probe package (`ruu_probe/android-info.txt` with the device's
own `modelid: 0P6B20000`, `cidnum: VZW__001`, `mainver: 6.21.605.3`,
`hbootpreupdate: 11`), rebooted into RUU mode and uploaded it:

```
fastboot oem rebootRUU          -> OKAY
fastboot flash zip probe.zip
  Sending 'zip' (0 KB)   OKAY
  Writing 'zip'   (bootloader) signature checking...
  FAILED (remote: '12 signature verify fail')
```

So the ZIP container **is** cryptographically checked before anything is
parsed or applied (the `12` is the same `FAIL12 signature verify fail`
string at `0x0f5959fd`), and the metadata checks in `f50b278` are only
reached afterwards, for an already-trusted package. The "no crypto in the
apply path" observation was correct but irrelevant: the gate sits in front
of it.

---

## 11. `fastboot erase` — new primitive, but it honours the protection list

Measured while LOCKED and S-ON:

```
fastboot erase cache        -> Erasing 'cache' OKAY            (unprotected partition)
fastboot erase tool_diag    -> FAILED (remote: 'not allowed')  (TZ/MPU-protected)
fastboot erase reserve_3    -> FAILED (remote: 'not allowed')  (TZ/MPU-protected)
```

So erase needs no signature (unlike flash) but hboot itself refuses the
protected partitions (`Access denied. %X~%X is protected by TZ.` is in that
code path). That closes the "erase pg1fs to drop the secure flag" idea —
pg1fs cannot be erased from fastboot either.

Side observation: `misc` is actively written by hboot — the current dump
differs from the earlier one only at offset 0x138 with the ASCII
`HPST_NV_SUCCESS` left behind by the user's earlier `oem refurbish` run.
That confirms misc is hboot-writable working state, and it is also
AP-writable (root), i.e. the one shared communication channel.

## 12. Where the boot-command codes go

The `misc` BCB dispatcher stores the command code at `config+0x1597C`
(`0x0f50e3c0`) and the only consumer is `0x0f50e7f8`-`0x0f50e824`, which
maps codes to boot modes:

```
code values seen: 3, 0x12..0x1b, 0x29..0x2b, 0x2d, 0x31 ...
0x0f50e810: if (code == 0x17) return 0            ; special-cased
else return code
```

`EnterMfgkernel` (mfg kernel boot), `Enter9kRD*` (9000-series diag modes),
`EnterSDupdate`, `update-hboot`, `update-zip`, `boot-repartition` and
`RebootATS` are the interesting codes. The next audit is what each code
does downstream — in particular whether any of them reads its payload from
a partition the AP *can* write (`reserve` p43, `cache` p48, `custdata`
p22, `pdata` p29, `misc` p24 are all AP-writable).

**Checked the payload source for the engineering modes:** the `mfg`
partition (p5, 256 KB) is effectively empty — its first 4 KB contain only
38 non-zero bytes (a 20-byte header `6036ee00 02000000 03000000 1c000000
5e2354c8`), no `ANDROID!` boot header, no kernel or ramdisk. `sp1` (p12,
5 MB) is filled with a repeating `9df7` filler pattern. So `EnterMfgkernel`
has nothing to boot on this device and that route is dead too — as is any
"boot an engineering kernel" idea that assumes one is stored locally.

Remaining classes of route, in order of tractability:

1. A memory-safety bug in code that runs **before** a signature check
   (upload buffers, USB stack, the 0x100-byte signature-block handling).
2. An SD-card based update (needs physical media the device does not have,
   and the images are signature-checked anyway).
3. Physical routes: HTC service keycard (JavaCard), or the TZ bug that the
   earlier sessions already showed is hardened on this build.

---

## 6. New reachable surface: the `misc` BCB command dispatcher

`misc` (mmcblk0p24) **is writable from Android with root** (measured), and
hboot runs a string dispatcher over a boot-control record at every boot.
String table (`0x0f50dd00`–`0x0f50e600`):

```
H_R_PreUpdate      boot-repartition   update-hboot
update-zip         update-zip-repartition  update-combo
SetRuuNbhUpdate    EnterSDupdate      EnterBootloader
ImageUpdateFail    EnterFastboot      Reboot
RebootATS          EnterMfgkernel     Enter9kRD / Enter9kRD2SD
Enter9kRD2INTSD    Enter9kRDARB       EnterRPowertest
EnterInstallCW     Gencheckpt_S/_H/_B DeviceColdBoot
DeviceWarmBoot     EnterMinikernel    EnterSimlock
EnterHTMix         EnterHTDdr         Krouter1SPRD …
```

Each match stores a command code into `config_block + 0x1597C`
(`0x0f50e3b6`) and then calls the executor at `0x0f530048`. The classic
recovery trio is visible too (`recovery\n--wipe_all\n`,
`recovery\n--wipe_data\n`, `format "fat"`).

Consequences:

* The `update-*` codes drive hboot's **RUU/zip engine** ("common/sdupdate",
  `recovery_flash_zip`, `[RECOVERY_ERR] security check failed!`,
  `adopting the signature contained in this image...`). Sourcing it needs
  an SD card (`sd_check_image_error: HBoot3/Boot/Recovery image …`) and the
  images are signed, but the parser is a reachable attacker-controlled
  surface once a card is present.
* `RebootATS` sets boot-command 0x2e; it is the only ATS-related boot
  command in the table.
* Writing `misc` is therefore the cheapest way to steer hboot's boot-time
  behaviour from the AP, and it is the recommended starting point for any
  further hboot fuzzing/RE.

### The ATS state machine is wired to that dispatcher

`f530048` (the ATS enable state machine, the only writer of the persistent
ATS debug flag) has exactly **one** caller in the whole image:

```
0x0f50e406  bl f530048        <- the BCB command executor
```

and its first act is `if (!f53b5f8()) return;` — i.e. it only runs on a
S-ON device. It then reads an ATS record through `f541870()` and checks for
the magics `ISML` (0x4d4c5349) / `MLML` (0x4d4c4d4c) before calling the same
`f566ed4()` "keycard" service that gates `writesecureflag`.

So the *only* software path that can set `security[0x400]` (disable eMMC
write protection for the next boot) is: a BCB command in `misc` → the ATS
record check → the keycard/ATS service. A valid ATS record plus the
service's OK byte are still required; the record's origin is what a future
session should chase (`f541870` reads it out of a RAM structure whose
contents are populated at boot).
