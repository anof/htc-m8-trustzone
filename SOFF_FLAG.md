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
