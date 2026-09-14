# HOWTO: S-OFF **and** bootloader-unlock an HTC One (M8) Verizon from software

This is the practical runbook.  It is the condensed, ordered version of
everything in this repo, and it is the exact sequence that worked on
`HT45FSF02406` (HTC6525LVW, MID `0P6B20000`, hboot `3.19.0.0000`, firmware
`4.17.605.17`, CID `VZW__001`).  End state reached:

```
fastboot getvar security            -> security: off          (S-OFF)
fastboot oem refurbish unlockstatus -> device unlocked!!     (UNLOCKED)
TWRP 3.7.0-9 installed, LineageOS 19.1 (Android 12) installed and booting
```

No HTCdev token, no keycard, no paid tool, no EDL — everything below happens
from a root shell on the phone plus `adb`/`fastboot`.

Plan for ~1 hour of work, most of it waiting on reboots.

---

## 0. What you need

* The phone, a USB cable, a Mac or Linux box with `adb` + `fastboot`
  (platform-tools) and `python3`.
* **Root on the phone — twice.**  Once to write the S-OFF flag, and once
  more after the reboot that follows it, to write the unlock flag (the
  reboot destroys temporary root).  On stock 4.17.605.17 (Android 5.0.1)
  that means KingRoot 4.5.0
  (`com.kingroot.kinguser-4.5.0-120-minAPI8.apk`, kept locally, not
  committed here); §4 also gives a root-free alternative (a boot image with
  `ro.secure=0` flashed through RUU mode).  See the warning in §3: once you
  start the S-OFF step, do not reboot until the flag is written — the
  window in which the card is writable belongs to that boot session.
* An LLVM cross toolchain (`brew install llvm` on a Mac).  Binaries are not
  committed here (`.gitignore` drops `*.ko`, `*.o`, `*.img`), so build the
  three pieces once with `tools/build_emmcwp.sh`,
  `tools/build_insmod_mmap.sh` and `tools/kmod_emmcpwr/build12.sh`.
  The `__versions` CRC table in `emmcpwr12_meta.c` is for the `3.4.0` kernel
  of firmware `4.17.605.17`; another firmware needs a rebuild of that table
  (§7).  Everything else is firmware-independent.

## 1. Baseline: record what you have before touching anything

```
adb devices
adb shell getprop ro.build.display.id
adb shell cat /proc/version                      # kernel build string
adb reboot bootloader
fastboot getvar all                              # hboot, MID, CID, mainver
fastboot oem readsecureflag                      # secure_flag: 3 = S-ON
fastboot reboot
```

Write those four values down.  Everything in this repo is keyed to
`hboot 3.19.0.0000` / `mid 0P6B20000` / `tz TZ.BF.2.0-2.0.0114`.

If you have root, take a dump of the firmware partitions now (you cannot
do this later without root, and it is your undo button):

```
adb shell su -c 'dd if=/dev/block/mmcblk0p2  of=/data/local/tmp/pg1fs.img  bs=65536'
adb shell su -c 'dd if=/dev/block/mmcblk0p11 of=/data/local/tmp/hboot.img  bs=65536'
adb shell su -c 'dd if=/dev/block/mmcblk0p1  of=/data/local/tmp/sbl1.img   bs=65536'
adb shell su -c 'dd if=/dev/block/mmcblk0p9  of=/data/local/tmp/tz.img     bs=65536'
adb shell su -c 'dd if=/dev/block/mmcblk0p8  of=/data/local/tmp/rpm.img    bs=65536'
for f in pg1fs hboot sbl1 tz rpm; do adb pull /data/local/tmp/$f.img; done
```

## 2. Get the tools onto the phone

### Getting root in the first place

On stock `4.17.605.17` the only root we found without unlocking is KingRoot's
temporary root:

```
adb install com.kingroot.kinguser-4.5.0-120-minAPI8.apk
python3 edl_tools/ensure_root.py      # wakes the screen, taps "TRY TO ROOT"
adb shell su -c id                    # uid=0(root)
```

`ensure_root.py` is unattended: it reads the UI hierarchy, taps the root
button whenever it appears, waits for `/system/xbin/su`, and saves
screenshots under `/tmp/root_shots/`.  The root is **temporary** — it is lost
on every reboot — but that is enough: the S-OFF flag is written to flash, so
after the reboot in §3 you simply re-root once more to do the unlock write
(§4).

```
# one-time build (outputs land next to their sources)
tools/build_emmcwp.sh
tools/build_insmod_mmap.sh
tools/kmod_emmcpwr/build12.sh

adb push tools/emmcwp                    /data/local/tmp/
adb push tools/insmod_mmap               /data/local/tmp/
adb push tools/kmod_emmcpwr/emmcpwr12.ko /data/local/tmp/
adb shell su -c 'mkdir -p /dev/soff
  cp /data/local/tmp/emmcwp /data/local/tmp/insmod_mmap /data/local/tmp/emmcpwr12.ko /dev/soff/
  chmod 755 /dev/soff/emmcwp /dev/soff/insmod_mmap
  chmod 644 /dev/soff/emmcpwr12.ko
  ls -l /dev/soff/'
```

`/dev` is tmpfs: the tools survive the moment when the eMMC disappears.
Do the staging in `/dev`, not in `/data`.

## 3. Phase 1 — S-OFF

### Why this is possible at all (30 seconds of theory)

The flag is the first dword of the `security` file inside the `pg1fs`
partition (partition start LBA 2082, flag sector **LBA 2148**, byte offset
`0x8400`).  hboot arms hardware write protection over the first 384 MiB on
every boot (`CMD6 EXT_CSD[171] = PWR_WP_EN`, then `CMD28` for groups 0..23),
so the sector is readable but every write is silently dropped.

`PWR_WP` is volatile: it only clears on a real **VCC power cycle of the
card**.  The main eMMC rail is `pm8941_l20`.  `regulator_force_disable()`
looks like it works but leaves `use_count` alone, and the normal
`regulator_enable()` path refuses to touch an always-on rail — so the cut
looks one-way.  The way out is to call the **driver ops directly** (exactly
what `_regulator_force_disable()` does internally): `desc->ops->disable()`
really cuts VCC, `desc->ops->enable()` really brings it back, and then the
card is re-initialised.  That is what `emmcpwr12.ko` does.  Full write-up:
`EMMC_WP_VOLATILE.md`, `SOFF_FLAG.md`, `FINAL_VERDICT_SOFF.md` (see the
correction at the top of that last file).

### Steps

1. Root shell, screen stays ON (a suspended host makes card re-init fail),
   and make `/data` forgiving before anything else:

   ```
   adb shell su -c 'svc power stayon true'
   adb shell su -c 'mount -o remount,errors=continue /data'
   ```

2. Disable the card's background GC so nothing writes to the card while it
   is being power-cycled, and confirm the card is idle:

   ```
   adb shell su -c '/dev/soff/emmcwp stat'      # want: card state = 4 (TRAN)
   adb shell su -c '/dev/soff/emmcwp sw 163 0'  # EXT_CSD BKOPS_EN = 0
   ```

3. Confirm the protection is real (this is your "before" measurement):

   ```
   adb shell su -c '/dev/soff/emmcwp type 0 1'
   #  group 0  lba 0..32767  type=2 POWER-ON
   adb shell su -c '/dev/soff/emmcwp wtest 4130'
   #  => write discarded / protected   (LBA 4130 is an unused scratch sector
   #     in the same 16 MiB group as the flag, so testing it is safe)
   ```

4. Power-cycle the card and write the flag, in one shot:

   ```
   adb shell su -c 'sync; mount -o remount,ro /cache; mount -o remount,ro /data
     /dev/soff/insmod_mmap /dev/soff/emmcpwr12.ko
     sleep 4
     /dev/soff/emmcwp type 0 1        # expect: type=0 none  (PWR_WP gone)
     /dev/soff/emmcwp wtest 4130      # expect: WRITE LANDED
     /dev/soff/emmcwp flagsoff        # writes dword 0 = 0 and verifies
     /dev/soff/emmcwp flagread        # expect: security_level = 0 (S-OFF)
     mount -o remount,rw /data; mount -o remount,rw /cache'
   ```

   `insmod_mmap` prints `init_module -> 0` and the kernel log shows
   `emmcpwr12: ... cut=1 ... card back`.  The tool backs the original sector
   up to `/data/local/tmp/security_lba_backup.bin` before writing.

5. Reboot and verify from the bootloader:

   ```
   adb reboot bootloader
   fastboot oem readsecureflag      # secure_flag: 0
   fastboot getvar security         # security: off
   ```

That is S-OFF.  **Only the first dword changed** — on our device the whole
pg1fs partition differed from the pre-S-OFF dump by exactly one byte.

### If step 4 does not behave

| symptom | meaning / fix |
|---|---|
| `insmod_mmap` prints `-20..-28` | module did not match this kernel (vermagic/CRC) or no `mmc0` found — rebuild the module, §7 |
| `-41 RAIL DID NOT COME BACK` | the rail stayed down: **reboot** (that is safe: nothing was written) and retry with the screen on and the card idle |
| `-24` | `mmc_suspend_host` failed, usually because the screen went off — keep it awake |
| `mmc_reinit -> -5/-22` | card re-init failed; retry the whole step with the device awake |
| `type` still shows POWER-ON after the cut | the module never really cut VCC; check dmesg for `cmcpwr12:` lines |
| module loads but the cut is one-way (device freezes) | you are running the older `regulator_force_disable` variant; use `emmcpwr12.ko`, which calls the driver ops directly |

## 4. Phase 2 — bootloader unlock

**You need root again here.**  The reboot in §3 wiped KingRoot's temporary
root (that is expected — the S-OFF flag itself is on flash and survives).
Either re-run the KingRoot flow from §2, or boot a rooted image: build one
with `tools/build_root_boot.py <stock boot.img> <out.img>` (it flips
`ro.secure`/`ro.adb.secure` so adbd runs as root), pack it with
`tools/build_ruu_zip.py`, and flash it through RUU mode — that is the route
used on the device this repo was written on, and it needs no APK at all.

The lock state is **dword 1 of the same `pg1fs_security` file (LBA 2148,
byte offset 4)**.  hboot's own writer stores `"HTCU"` (`48 54 43 55`) for
unlocked, `"HTCL"` for relocked, and `0` for locked; anything else decodes
as locked.  Details and hboot code addresses: `BOOTLOADER_UNLOCK_FLAG.md`.

The good news: **once the phone is S-OFF, hboot stops arming the eMMC write
protection**, so this write needs no power-cycle trick:

```
adb shell su -c '/dev/soff/emmcwp type 0 1'   # expect: type=0 none
adb shell su -c '/dev/soff/emmcwp wtest 4130' # expect: WRITE LANDED
```

If group 0 *is* still protected, run §3 step 4 (the power-cycle) and do the
unlock write in that same session, before the next reboot.

Then:

```
adb shell su -c 'dd if=/dev/block/mmcblk0p2 of=/data/local/tmp/pg1fs_pre_unlock.img bs=65536'
adb pull /data/local/tmp/pg1fs_pre_unlock.img
adb shell su -c '/dev/soff/emmcwp flagunlock'
#   before: security_level=0 unlock=0x00000000 jtag_dis=1
#   unlock tag now = 0x55435448 (HTCU / UNLOCKED)
adb shell su -c '/dev/soff/emmcwp flagread'
```

`flagunlock` refuses to write unless the sector really looks like
`pg1fs_security` (`level <= 1`, `jtag_disable == 1`, zero tail), and backs
the sector up first.

Reboot and verify:

```
adb reboot bootloader
fastboot oem refurbish unlockstatus   # (bootloader) device unlocked!!
```

The bootloader banner now reads `*** UNLOCKED ***`.

> Interesting side effect: the HTCdev gate that refuses this model is a
> `strcmp` against the CID (`"VZW__001"`) plus an RSA-2048 token check.
> Editing the flag bypasses both, because hboot only ever reads dword 1
> back.  See `HBOOT_ANALYSIS.md` §"unlock gate".

## 5. Phase 3 — TWRP and a modern LineageOS

Two hboot quirks decide the whole procedure:

1. **The kernel cmdline must be short.**  hboot appends ~900 bytes of its
   own debug text to the cmdline inside a 1024-byte buffer.  TWRP and
   Lineage boot images ship 130–160-byte cmdlines, which overflows the
   buffer and kills hboot (`hboot exception`, `kp attempted to kill init`,
   recovery that never starts).  Rewrite the cmdline to 25–56 bytes:

   ```
   python3 tools/patch_boot_cmdline.py twrp.img twrp_short.img
   # cmdline 153 -> 25 bytes: androidboot.hardware=qcom
   ```

2. **RUU zips still work while LOCKED** (useful before the unlock, and as
   your rescue path afterwards): `fastboot oem rebootRUU` +
   `fastboot flash zip <zip>` + `fastboot reboot`, with the zip capped at
   1 GiB (`tools/build_ruu_zip.py`).  Entries named `misc`/`userdata` are
   ignored by hboot.

TWRP:

```
fastboot flash recovery twrp_short.img     # only accepted after the unlock
adb reboot recovery                        # TWRP 3.7.0-9-0-m8 boots
```

ROM install (unattended, no touch input needed):

```
adb push lineage-19.1-*-UNOFFICIAL-m8.zip /sdcard/lineage19.zip
adb shell 'mkdir -p /cache/recovery
  printf "install /sdcard/lineage19.zip\n" > /cache/recovery/openrecoveryscript'
adb reboot recovery        # TWRP processes the script on start, writes system
```

While it writes you can watch:
`adb shell tail -f /tmp/recovery.log` — it prints `writing 1024 blocks of
new data` for a few minutes.  Notes:

* keep the zip on `/sdcard` — a TWRP "wipe data" formats `/cache`, so
  anything parked there disappears;
* `twrp install ...` over adb works too, but commands issued too close
  together hit `Another threaded action is already running` — the
  openrecoveryscript route is the reliable one;
* the ROM's own `boot.img` has a 129-byte cmdline, so immediately after the
  install flash the patched one (the device is unlocked now, direct flash
  works):

```
python3 tools/patch_boot_cmdline.py boot19.img boot19_short.img \
        "androidboot.hardware=qcom androidboot.selinux=permissive"
fastboot flash boot boot19_short.img
fastboot reboot
```

Verified hashes for the ROM used here:

```
lineage-19.1-20220825-UNOFFICIAL-m8.zip
  sha1   3544ec5fdd0208526e193726a2a221ba54dcbf0a
  size   583049840
```

## 6. Rescue paths, in order of preference

1. **Phone boots, you have root** — write the flag back
   (`emmcwp flagsoff` / restore the sector or the whole `pg1fs` dump), or
   re-run §4.
2. **Phone boots to fastboot** — you can always flash while unlocked
   (`fastboot flash boot/system/recovery`), or while locked via an RUU zip
   (§5 quirk 2).  A boot image that hboot rejects does **not** damage the
   partition: hboot verifies before writing.
3. **Recovery loops / hboot exception** — that is the cmdline overflow, not
   a brick: reflash a short-cmdline image.
4. **Worst case** — the whole `pg1fs` partition can be written back from
   the dump with `dd` from any root shell (TWRP works even with a broken
   Android).

Things that are *not* damaged by this procedure: hboot, sbl1, tz, rpm,
radio, and the two flags are single dwords in `pg1fs`.  `oem writesecureflag`
and `fastboot flash unlocktoken` are never used.

## 7. Rebuilding the tools (only if the prebuilt ones do not match)

**ARM userland tools** (`emmcwp`, `insmod_mmap`) are dynamically linked
against the phone's own bionic.  Get the reader libs once:

```
mkdir -p androidlib && cd androidlib
adb pull /system/lib/libc.so
adb pull /system/bin/linker
```

then `tools/build_emmcwp.sh` and `tools/build_insmod_mmap.sh`
(`LLVM=/path/to/llvm/bin`).

**The kernel module** must match the target kernel exactly: same vermagic,
same symbol CRCs if `CONFIG_MODVERSIONS` is on (it is on HTC's stock kernel),
same struct offsets.  `tools/kmod_emmcpwr/emmcpwr12_meta.c` holds the
`__versions` CRCs for firmware 4.17.605.17 and `build12.sh` builds it.
For different firmware you must regenerate the CRCs from that kernel's
`__kcrctab`: read the symbol addresses from `/proc/kallsyms` (root), map the
`__crc_*` values out of the kernel image, and paste them into the meta file.
The module deliberately uses `kallsyms_lookup_name()` for everything it
calls, so no symbol table entries are needed beyond the CRCs.

## 8. File map

| file | why you care |
|---|---|
| `SECOND_DEVICE_HOWTO.md` | this runbook |
| `BOOTLOADER_UNLOCK_FLAG.md` | the unlock flag: hboot addresses, values, proof |
| `SOFF_FLAG.md` | the S-OFF flag: location, semantics, hboot writer, WP map |
| `EMMC_WP_VOLATILE.md`, `EMMC_WP_BYPASS.md` | why PWR_WP is volatile and what was tried |
| `FINAL_VERDICT_SOFF.md` | the (now corrected) "impossible" analysis — useful history |
| `HBOOT_ANALYSIS.md` | hboot reversing: command table, CID gate, token verifier |
| `tools/emmcwp.c` | `type/wtest/flagread/flagsoff/flagunlock/rd/wr/...` |
| `tools/insmod_mmap.c` | loads a `.ko` by `mmap`+`init_module(2)` |
| `tools/kmod_emmcpwr/emmcpwr12.c` | the VCC power-cycle: driver ops + re-init |
| `tools/build_emmcwp.sh`, `build_insmod_mmap.sh`, `build12.sh` | rebuilds |
| `tools/patch_boot_cmdline.py` | shortens a boot image cmdline (the hboot trap) |
| `tools/build_ruu_zip.py` | builds an RUU zip for the while-locked write path |
| `tools/build_root_boot.py` | patches `ro.secure`/`ro.adb.secure` in a boot ramdisk (root adbd) |
| `edl_tools/ensure_root.py` | unattended KingRoot re-root helper |
