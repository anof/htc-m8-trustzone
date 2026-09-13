# State of the hunt — unlocking a Verizon HTC One (M8), software only

## 2026-09-13 (afternoon, phone unplugged) — **CORRECTION: the flag is
## probably writable from Android after all**

The "hardware write-protect, nothing can clear it" conclusion below is
wrong in its *mechanism*, and that matters. Re-reading
`partition_write_prot_mmc` (`0x0f504a30`) end to end shows hboot arming the
eMMC's own **write-protect groups** — CMD28 one group at a time, group size
`512KB * HC_WP_GRP_SIZE * HC_ERASE_GRP_SIZE` — not SoC registers, and
`CLEAR_WRITE_PROT` (CMD29) is the matching clear. Our card reports
`HC_WP_GRP_SIZE=32, HC_ERASE_GRP_SIZE=1` (16 MiB groups) and
`USER_WP=0x00`, i.e. the groups hboot armed are **Temporary** type, which
CMD29 clears. `pg1fs_security` has no CRC and no signature (only bytes 0
and 8 are non-zero), so flipping it is a 4-byte write to LBA 2148.

The earlier "it can't be cleared" evidence came from probes that (a) never
read the WP *type* (CMD31), (b) wrote the wrong EXT_CSD byte (166 instead of
171) and (c) never decoded the R1 status word. See
[EMMC_WP_BYPASS.md](EMMC_WP_BYPASS.md) for the full analysis, the new
`tools/emmcwp.c` (MMC_IOC_CMD tool with CMD31/CMD30/CMD29/CMD28, R1
decoding, and a safe scratch write test at `pg1fs+1MiB` in the same 16 MiB
group as the flag) and `tools/soff_run.sh` (unattended run + bootloader
verification). Public corroboration: CVE-2014-9961, "a vulnerability in
eMMC write protection exists that can be used to bypass power-on write
protection".

## 2026-09-13, 03:00–04:00 — **EDL entry is real and reproducible**

**Short version:** the M8 *does* expose Qualcomm EDL (Sahara). It is not
reachable by any key combo; it is entered by writing Qualcomm's
emergency-download magic triple into IMEM and resetting. We did that from a
kernel module, watched the device come up as `QHSUSB__BULK 05c6:9008`, and
completed Sahara handshakes and image uploads with it.

### How EDL was entered

Kernel source (`arch/arm/mach-msm/restart.c`) shows the `reboot edl` path
writes three magics to IMEM before resetting:

```
EMERGENCY_DLOAD_MODE_ADDR 0xFE0   ->  0xFE805FE0
MAGIC1 0x322A4F99, MAGIC2 0xC67E4350, MAGIC3 0x77777777
```

That path is compiled out of this HTC kernel (`CONFIG_MSM_DLOAD_MODE` off —
the string "dload mode is not enabled on target" is present), so
`adb reboot edl` does nothing. We wrote the magics ourselves from a loadable
module (`kmod/dload/dloadmod.c`, build recipe `kmod/dload/build.sh`) using the
`__arm_ioremap` symbol fingerprint taken from a stock module's `__versions`.

With the magics set, the next warm reboot comes up as **05c6:9008
(QHSUSB__BULK)** for ≈18 s, then the watchdog resets the phone and it boots
Android normally. The trigger is one-shot.

### What the EDL session answers

```
HELLO v2 min 1 max_pkt 0x400 mode 0
HWID:    0x007b80e100000000   (MSM_ID 0x007b80e1 = MSM8974Pro, OEM 0, MODEL 0)
PK_HASH: ba2102da99c924058c758fa9f4250847c92cabde17fdcef01d4daff8df5d6753
Serial:  0x09761bfe
```

The boot ROM also serves `EXECUTE` commands (serial, HWID, PK hash) and
accepts an image for Sahara image-ID **13**, requesting exactly the bytes the
MBN header declares (verified: 65,668/65,668 bytes, zero padding).

### The wall: signature enforcement

Ten different public Firehose programmers (ZTE/OPPO/Xiaomi/Qualcomm reference,
MSM8974/8974AB/8974Pro/AC) all upload successfully — the boot ROM answers
`END_TRANSFER status=0` and `DONE_RSP` — and then **nothing happens**: the USB
device stays enumerated but never services another endpoint transaction, and
the 18 s watchdog resets the phone. Identical behaviour for a modified image
whose entry code was replaced with a marker writer (no marker appeared) and
for a payload that pets the watchdog / stops the USB controller.

Positive control: uploading the phone's **own HTC-signed SBL1** as the image
makes the device drop off the bus 0.28 s after the upload and boot the normal
chain — i.e. the boot ROM authenticates images and only executes those signed
with the device's key (PK hash above, HTC's).

So EDL is confirmed, but it only runs **HTC-signed** images, and no HTC-signed
Firehose programmer for this platform is public. Remaining ideas in this
direction: (a) locate an HTC-signed programmer (service firmware/RUU leaks),
(b) abuse the pre-auth MBN parsing in the boot ROM (load address is taken from
the header), (c) run the SBL1 in EDL and use *its* download mode.

Tools built for this: `edl_prep/` (candidate programmers), `s1_firehose.py`
(one-window Sahara upload + Firehose handover), `try_loader.sh` /
`night_loop.sh` (unattended cycles), `ensure_root.py` (UI-dump driven KingRoot
automation), `kmod/dload` (magics), `kmod/dloadrd` (read back IMEM markers).

## 2026-09-13, 04:00 — the IMEM slot is the HTC *restart reason*

The kernel header `arch/arm/mach-msm/include/mach/htc_restart_handler.h`
defines exactly the values hboot writes into IMEM `0xFE80565C`:

```
RESTART_REASON_BOOT_BASE   0x77665500
  BOOTLOADER 0x77665500   REBOOT 0x77665501   RECOVERY 0x77665502
  ERASE_EFS  0x77665503   RAMDUMP 0x776655AA  POWEROFF 0x776655BB
  ERASE_FLASH 0x776655EF
RESTART_REASON_OEM_BASE    0x6F656D00 | code
```

So the "dload magics" seen earlier are really HTC restart reasons: hboot writes
`0x77665501` (reboot) when its `to_sbldload` path asks for a download window,
and the `0x776655aa` read back after boots is the RAMDUMP reason.

hboot has a boot-mode table (`androidboot.mode=...`: `normal`, `recovery`,
`recovery_manual`, `gift_mode`, `repartition`, `power_test`,
`offmode_charging`, `mfgkernel`, `9kramdump*`, router modes) at
`0x0F5A0D28`+, plus `resetgift` / `boot-repartition` /
`update-zip-repartition` handling and a "gift file" mechanism.

**The eMMC write protection is only armed for boot modes 3 and 0xe**, so the
next experiment is: drive hboot into another mode (restart reason / OEM code /
gift / repartition) that still reaches a usable system, then write the S-OFF
dword from that environment. Raw eMMC attempts from normal-mode Android
(CMD29 / EXT_CSD[166] write / CMD24) are all silently discarded, consistent
with the arming being done by hboot rather than the card.

Device: `HT45FSF02406`, HTC6525LVW (`m8_wlv`), MID `0P6B20000`,
CID `VZW__001`, hboot 3.19.0.0000, firmware 4.17.605.17, Android 5.0.1,
MSM8974, S-ON, bootloader LOCKED. Root available only via KingRoot
(temporary; lost on every reboot, re-obtainable from the Mac with
`monkey -p com.kingroot.kinguser ...` + `input tap 540 1553`).

Goal: get the device to a state where LineageOS can be installed, without
any physical help (no SD card, no keycard, no second device).

## The two things that would each be sufficient

1. **Bootloader UNLOCK.** hboot's local gate is a `strncmp(cid, "VZW__001")`
   (`0x0f503590`), so unlocking needs an HTCdev RSA token. HTCdev refuses
   this device (`Error 172: CID Not Allowed (MID not exist in Model Rule)`),
   and the token is RSA-verified by TZ/hboot, so it cannot be forged.
2. **S-OFF.** The secure flag is the **first dword of the `security` file in
   the `pg1fs` partition** (partition offset `0x8400`, absolute LBA 2148):
   `>1` = S-ON, `<=1` = S-OFF (`f50e7a8` / `f5318dc` / `f531898`).
   Current value: `3`.

## Everything measured, and why each route is closed

| route | evidence | verdict |
|---|---|---|
| Write the S-OFF flag from Android | `pwrite` + raw eMMC CMD24 both silently dropped on pg1fs; misc/pdata/cache/radio writable for comparison | hardware write-protect (hboot arms it each boot via `msm_mpu_emmc_protect`) |
| `oem writesecureflag 0` | `[JAVACARD_ERR] SD/USBDISK Init error`, `Permission denied, value 1`; `checkKeycardID` = -1 | needs HTC JavaCard keycard |
| ATS bypass (disables the eMMC WP) | `f52fdf8 && f53031c` gate; input `atsdeb.txt` opened via the SD/FAT API; `oem ats 1` only sets a RAM flag (visible as `ats=1` in the kernel cmdline) | needs a physical SD card + signed ATS blob |
| `fastboot flash <partition>` | all targets reachable, then `signature checking... FAILED (signature verify fail)` | HTC signature required |
| `fastboot flash zimage/rzimage/ramdisk` | falls through to the same verifier before the rebuild dispatcher `0x0f51c858` | signature-gated |
| `fastboot flash zip` / RUU mode | `fastboot oem rebootRUU` OK, then `FAILED (remote: '12 signature verify fail')` with a hand-built package carrying the device's own MID/CID/version | signature-gated (measured) |
| `fastboot erase pg1fs` (drop the flag by erasing) | `erase cache` OKAY, but `erase tool_diag` / `erase reserve_3` -> `not allowed` | protection list enforced for erase |
| Engineering modes via `misc` BCB (`EnterMfgkernel`, `Enter9kRD*`) | `mfg` (p5) has 38 non-zero bytes and no boot header; `sp1` is filler | nothing to boot |
| TZ exploit (published MSM8974 route) | all secure-address writes refused (`0xffffffee`); keymaster CVE-2016-5349 built and works but reads zeros (XPU) | hardened on this build |
| XTC/trustlets (widevine, keymaster, cmnlib) | widevine lacks the PRDiag family; cmnlib is a library with no command table; no public cmnlib vuln | dead |
| CID change (misc copy is writable) | CID used by hboot comes from `board_info` +0x14 (XPU), not misc; misc only carries hboot's own working state | dead |

## Why nothing running *after* hboot helps

The eMMC write protection on boot/recovery/system/firmware is armed by hboot
on every boot and enforced below the OS (raw MMC writes are dropped too).
TWRP, a custom recovery, or a custom kernel therefore still could not write
those partitions. Only TZ or hboot can, and every hboot write path is gated
by one of: the JavaCard, a signed ATS blob, or HTC's signature.

## What is left

1. **A memory-safety bug in hboot, in code that runs before a signature
   check.** Reachable input: the `download:` payload buffer (transport
   `0x0f51d5e4`; state globals `0x0F6A5F4C` buffer, `0x0F6A5E40` counters),
   the 0x100-byte signature-block path, USB descriptors. (The `oem` command
   parser was already audited: no attacker-controlled length reaches a
   copy.)
2. **External material**: a microSD card (ATS provisioning blob) or HTC's
   service JavaCard.

## Leads examined and parked

* **SunShine APK** (the 237 MB `SunShine-latest.apk` on the Mac):
  confirmed genuine — dex package `com.streamlinedmobile.sunshine3`
  (Streamlined Mobile), assets `blob1..blob45`, `bloba1..bloba12`, `zero`,
  `supersu`. Every blob shares a 20-byte high-entropy prefix
  (`6bc5685f 581a928f da13b13f b0f9bea4 a2eadf83 e7943e84`) and diverges
  after it; `zero` (141,024 bytes) has a different prefix. XOR-ing the
  blobs with `zero` yields a *shared* 30-byte prefix and then noise, so
  `zero` is not a simple XOR keystream. This is consistent with the public
  understanding of SunShine: the per-device payload is encrypted and the
  key/token comes from their (now dead) server. Recovering it offline would
  mean reversing the whole payload scheme with no known key material —
  parked, not pursued further.
* **Pre-verification buffers**: the `download:` transport loop
  (`0x0f51d5e4`) tracks `remaining`/pointer per USB transfer with a timeout
  and a 30 MB ceiling; the partition-write loop clamps to
  `min(remaining, chunk)` and validates the returned length. No bug spotted
  in either. hboot does not read any AP-writable partition for its security
  state (it reads board_info/pg1fs/pg2fs/misc + images; only misc is
  writable, and its data only feeds the audited BCB dispatch).

## Last unexplored reachable behaviour: `EnterMinikernel`

The `misc` BCB dispatcher (`0x0f50e28a`) maps the command
`EnterMinikernel` to boot-command code **0x31** (and copies the command
string into hboot's working record, `0x0f50e29e`). The code mapper at
`0x0f50e830` returns one of two strings for codes
`{3, 0x12..0x1b, 0x29..0x2b, 0x2d, 0x31}` — and the string
`"minikernel\n"` exists in the image (`0x0f5840d8`) with **no other
references**, i.e. it is reached via that table.

The Android kernel in this build contains no `minikernel` parameter
(checked `vmlinux.bin`), so this is an hboot-internal factory mode rather
than a kernel cmdline switch. What it does is not yet known.

**Not tested on purpose:** factory/diagnostic modes frequently wait for a
host tool on USB. A mode that blocks would leave the phone hung until
someone can power-cycle it, and the user is away — so this one stays
un-tested until they are back (or until the mode's code path is read end to
end, which is the next static task).

### Resolved: `EnterMinikernel` is just "boot recovery"

Followed the mapper's consumers (`0x0f514122`, `0x0f53b97c`). The function at
`0x0f53b970` takes the mapper's result and uses it **as a partition name**
for a `0x260`-byte image-header read (`f50410c` lookup, `f50456c` read), and
the mapper returns:

```
codes {3, 0x12..0x1b, 0x29..0x2b, 0x2d, 0x31} -> "recovery"
everything else                                -> "boot"
```

So the whole boot-command table is just a *boot-vs-recovery selector* (HTC
calls the stock recovery image the "minikernel"). `EnterMinikernel` = boot
into recovery; there is no privileged factory environment behind it. Lead
closed.

## ★ The boot command is writable input and it gates the eMMC WP ★

Corrected reading of `f50e7f8` (it returns the **boot command**, not a
config item):

```
f50e7f8:
   x = f50e7da()                    ; config_get(6) if (S-OFF || perm(0xa4)==0) else 0
   if (!(x & 0x1000))  return config[0x1597C]      ; the boot command
   if (config[0x1597C] == 0x17) return 0
   return config[0x1597C]
```

and every `partition_write_prot_mmc()` call is guarded by
`f50e7f8() ∈ {3, 0xe}` → **the eMMC write protection is armed only when the
boot command is 3 or 0xe; for every other command it is skipped.**

The boot command (`config+0x1597C`) is written by the `misc` BCB dispatcher
from the command string that **the AP can write** (`misc` offset 0x800
mirrors the dispatcher's record, whose base is the structure at
`0x0F64D548`; misc offset 0x20 holds the warm/cold marker, confirming the
mapping). Full command → code map extracted from the dispatcher:

| command | code | boot target (mapper) |
|---|---|---|
| `Reboot` | 1 | boot |
| `EnterFastboot` | 2 | boot |
| `update-hboot` | 5 | boot |
| `update-zip` | 6 | boot |
| `update-combo` | 7 | boot |
| `update-zip-repartition` | 8 | boot |
| `EnterBootloader` | 9 | boot |
| `EnterSDupdate` | 0xd | boot |
| `EnterRPowertest` | 0x10 | boot |
| `boot-repartition` | 0x18 | **recovery** |
| `EnterSimlock` | 0x1c | boot |
| `Enter9kRD/2SD/2INTSD/ARB` | 0x29–0x2d | **recovery** |
| `RebootATS` | 0x2e | boot |
| `EnterMinikernel` | 0x31 | **recovery** |
| `EnterHTMix` | 0x36 | boot |
| `ImageUpdateFail` | 0x39 | boot |
| `EnterInstallCW` | 3 | **arms the WP** |
| (default/fallback) | 0xe | **arms the WP** |

`config[6]` measured live as `0x5A5A5A5A` and `config[7]` as `0x5A5B5A5A`
(bit 16, set by the boot code at `0x0f53bdba`); `readconfig 0..12` all
readable via fastboot.

### Consequence / next experiment

Writing e.g. `ImageUpdateFail` (code 0x39, boots Android, no forced flow) or
`EnterHTMix` (0x36) into `misc+0x800` from Android (root) and rebooting
should bring Android up **without** the eMMC write protection armed — after
which root can write `pg1fs` (offset 0x8400, first dword = the S-OFF flag),
i.e. flip the device to S-OFF. All of the pieces for this test already
exist on the machine (`blkio` pwrite/pread, KingRoot re-root automation).

Risk note: if the chosen command triggers a flow that waits for a host tool,
the phone would hang until it can be power-cycled (user is away), so the
command choice should be the most inert one — the mapper shows the boot
command's only consumers are the WP gate and boot-vs-recovery selection, but
the individual handler bodies have not all been read yet.

### Tested live: the misc+0x800 write does nothing (offset inference was wrong)

```
# from Android (root), before reboot:
blkio w /dev/block/mmcblk0p24 0x800 5265626f6f7441545300...   ; "RebootATS"
blkio r /dev/block/mmcblk0p24 0x800 10  -> 5265626f6f74415453 00000000000000
# reboot:  Android boots normally (no hang), but...
blkio w /dev/block/mmcblk0p2 0x8600 aabb...   -> pwrite ok, read back 00...
blkio w /dev/block/mmcblk0p2 0x8400 <S-OFF>   -> (not attempted; WP still enforced)
# after the reboot:
blkio r /dev/block/mmcblk0p24 0x800 10 -> 5265626f6f74415453 00000000000000
```

So: (a) the device booted Android with the command present — the *command
string* itself is harmless; (b) the eMMC write protection was **still
enforced**; and (c) **hboot did not clear the field**, which strongly
suggests the BCB command hboot consumes is *not* at `misc+0x800` — the
record the dispatcher reads (structure at `0x0F64D548`) must be loaded from
somewhere else, or at a different offset.

Next step (precise): find the loader for that structure. hboot references
three misc partition names — `misc`, `misc2`, `misc3` (`0x0f595d18`,
`0x0f583c36`, `0x0f583c30`; xrefs at `0x0f50ca96`/`0x0f50cab4`/`0x0f50d20c`
and reads at `0x0f505352`, `0x0f506710`, `0x0f51cd40`, `0x0f51cfd8`) — so
HTC keeps redundant copies. Reading the reader/writer pair around
`0x0f50ca94` will give the real file layout and the offset of the command
field.

### Where the command field actually lives (the record is the *config block*)

Re-read the dispatcher's own pointer setup at `0x0f50df72`:

```
ldr.w r5, =0x197238 ; add r5, pc    -> r5 = 0x0F6A51B8
ldr   r5, [r5]                       -> r5 = *(0x0F6A51B8)  (the runtime config block)
add.w r4, r5, #0x800                 -> command string lives at config+0x800
```

So the command is read from the **runtime config block**, not from the misc
partition (my `misc+0x800` write was to the right *offset* of the wrong
*object* — hboot never consults that copy). Consistent with that: none of
the partitions on the device contain any of the command strings
(`RebootATS`, `update-zip`, `update-hboot`, `SetRuuNbhUpdate`, …) — checked
`board_info`, `pdata`, `misc`, `pg2fs` dumps directly. The only misc hit is
`DeviceWarmBoot` at 0x20, which is hboot's own *output* marker.

So the BCB command string is placed into the config block at runtime (by the
boot flow / fastboot side), and the config block itself is built from the
write-protected sources. **Conclusion: the "boot command → skip eMMC WP"
mechanism is real, but it is not reachable by writing any partition the AP
can touch.** It is the mechanism HTC's own RUU/factory flows use.

### Recovery-path check, and the one experiment that has been deliberately deferred

```
fastboot erase misc   -> FAILED (remote: 'not allowed')
```

So `misc` cannot be erased from fastboot either (hboot's erase allow-list is
narrower than the AP's write permissions — the AP *can* write misc with
root). Practical consequence: if a write to `misc` ever stops Android from
booting, there is **no** bootloader-side way to undo it; the only fix would
be root, which needs Android to boot.

One candidate remains untested because of exactly that: the HTC BCB may
store the command in the *first* field of the misc record (where the CID
string sits: `misc+0` holds `VZW__001`, and the dispatcher compares the
record's first bytes against `RebootATS` etc.). Writing a command there
would either (a) be consumed and give the WP-skip, or (b) be ignored, or
(c) interact with the CID/BCD logic and leave the phone booting straight
into recovery or not booting at all — with no way to restore `misc` without
root. **Deferred until the user is back and can power-cycle the device if
needed.** Before running it, the safe order is:

1. dump misc (backup exists: `misc_now.img`),
2. write the command at `misc+0`,
3. `adb reboot bootloader`, check `fastboot oem readcid` — if the CID is
   unchanged, the field is not the CID source and the write is safe to take
   further; if it changed, restore from the backup immediately.

### The WP-skip class is now closed: hboot only ever *arms* the protection

Followed the two remaining pieces:

* `partition_verify_prot_mmc` (`0x0f504b40`) walks the protection table
  (0x18-byte entries) and *test-writes* each protected range, printing
  `[ERR] partition_verify_prot_mmc: eMMC verify write protect fail` if a
  range turns out to be writable. It **checks**, it does not re-arm.
* `partition_write_prot_mmc` (`0x0f504a30`) has **25 call sites**, all in the
  boot flow (`0x0f56axxx`–`0x0f572xxx`), and every one that was inspected
  passes `r2 = 1` (the "set" argument). There is no caller that clears, and
  no `clear`/`unprotect` string anywhere in the image.

So the eMMC write-protect groups are **armed once and never cleared by
hboot**, and the "skip arming for non-3/0xe boot commands" behaviour only
affects a device whose protection was never armed (factory state). On this
device the protection is already armed, which is exactly why the live
`RebootATS` test changed nothing even though the command path was real.

This closes the whole WP-skip family of ideas: no writable input, no boot
mode and no boot command can un-protect the device because nothing in hboot
ever issues the "clear" vendor operation.

### Last hypothesis examined: "unsigned / zero-signature" images

Facts established:

* TWRP's `recovery-twrp-3.7.0_9-0-m8.img` is a **standard AOSP boot image**
  (`ANDROID!` magic at offset 0), whereas HTC's stock images carry a
  0x100-byte HTC block at offset 0 with `ANDROID!` at 0x100. That format
  difference is why `fastboot flash recovery twrp.img` can never pass the
  HTC verifier — there is no HTC signature block in the file at all.
* hboot's flash verifier (`f528648` -> `f52ab08`) is **hboot-local SHA-1**
  (the `0x14`-byte digest and the SHA-1 `σ1(x) = ROTR17 ^ ROTR19 ^ SHR10`
  round pattern are visible in `0x0f52ab6a`-`0x0f52ab82`) which is then
  compared against an RSA-decrypted signature — but the **boot-time**
  boot/recovery check is TZ-backed (`0x0f514276` -> SMC), so even a bypass
  of the *flash* verifier would not produce a bootable custom image.
* The remaining cheap probe (zero the 0x100-byte HTC block of the *stock*
  recovery dump and try to flash it) was deliberately **not run**: if it
  were accepted it would overwrite recovery with an image that cannot boot
  (TZ check) and cannot be restored (no signed stock image can be reflashed
  from fastboot — the stock dump itself fails the verifier). Risk with no
  possible payoff.

## Conclusion of the software-only hunt

Every route by which hboot could be made to change its own security state,
write protected storage, or accept modified code has been traced and
measured on this device, and all of them are gated by one of:

* HTC's RSA signatures (unlock token, every flash target, RUU packages),
* the HTC service JavaCard (`writesecureflag`, `writecid`, ATS enable),
* a signed ATS blob delivered from an SD card,
* the eMMC write-protect groups, which hboot arms and never clears,
* TrustZone (boot-image verification, and the XPU that blocks AP writes to
  the protected partitions).

Remaining options all require something external: HTC's keycard, a microSD
card with a valid ATS blob, a different (non-Verizon) M8, or a genuine 0-day
in TrustZone/hboot that this investigation did not find.

## Strongest remaining lead: the eMMC WP is armed per *boot mode*

Every `partition_write_prot_mmc()` call site is guarded like this
(e.g. `0x0f56aa60`):

```
bl f50e7f8            ; boot mode  (config item #6)
cmp r0, #3
beq  do_protect
cmp r0, #0xe
bne  skip             ; <- any other mode: NO eMMC write protection
do_protect: partition_write_prot_mmc(start, end, 1)
```

So the hardware write protection is **only armed when the boot mode is 3 or
0xe**. If the device can be brought up in a different mode while still
starting Android, the AP could write `pg1fs` — and root is enough to flip
the S-OFF dword.

Where the mode comes from: at `0x0f50ba36` hboot walks a list of
`name=value` strings (`sscanf`-style parse via `f53a678`) starting at
`[base+0x65C]`, and ORs the parsed values into config items 0..10 with the
setter `f50d5ec` — item #6 is the mode. `f50e7f8` then reads item #6 (with a
special case when bit 12 is set and boot-command == 0x17).

Next step: find which store that `name=value` list is read from (it is
indexed off the same 0x0F64xxxx block that the cmdline fragments come from)
and which values produce modes other than 3/0xe — ideally one that still
boots Android. If the list has an origin the AP can write (`misc`, `pdata`,
`custdata`), this becomes a real path.

## Tools in this repo that made it possible

`tools/xref2.py` (drift-free PC-relative string xrefs, 2730 refs),
`tools/xrefs.py` (verified single-target xref), `tools/blrefs.py` (call
graph), `tools/dump.py` (annotated Thumb disassembly), `tools/strrefs.py`,
`tools/wpmap.py` (AP-write protection map), plus the on-device tools
`mmcprobe`, `mmcrw`, `blkio`, `atsctl` and the kmod build recipe.
