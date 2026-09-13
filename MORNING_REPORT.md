# Morning report — 2026-09-13 night session

## TL;DR

**The phone is not S-OFF.** It is currently parked in HTC's recovery screen
(no USB stack until a menu entry is selected), so it needs **one button press**:
pick "reboot system now" (or hold power ~10 s, then power on). Nothing was
written to flash — `pg1fs` still reads `03000000` (S-ON, unchanged).

What *did* change is the map of the device: **EDL is real on this phone and we
can enter it on demand** — but the boot ROM authenticates the image it loads,
and only HTC-signed images run. That is the wall we hit, and it was proven, not
assumed (see below).

## What was proven tonight

### 1. EDL entry works (new)

Qualcomm emergency-download mode is entered by writing three magics into IMEM
and resetting:

```
0xFE805FE0 = 0x322A4F99
0xFE805FE4 = 0xC67E4350
0xFE805FE8 = 0x77777777
```

`adb reboot edl` does nothing here because the HTC kernel is built without
`CONFIG_MSM_DLOAD_MODE` (the "dload mode is not enabled on target" string is in
the kernel). We wrote the magics from a loadable module
(`edl_tools/kmod/dload/`) using the kernel's `__arm_ioremap` symbol fingerprint,
then triggered a warm reset.

The phone then enumerates as **`QHSUSB__BULK 05c6:9008`** for ≈18 s (watchdog
then resets it and Android boots). One-shot: needs re-arming each time.

### 2. The Sahara session answers everything we ask

```
HELLO v2 (min 1, max packet 0x400)
HWID     0x007b80e100000000  (MSM8974Pro, OEM 0, MODEL 0)
PK_HASH  ba2102da99c924058c758fa9f4250847c92cabde17fdcef01d4daff8df5d6753
Serial   0x09761bfe
```

`EXECUTE` commands (serial / HWID / PK hash) all work. The ROM accepts an image
for Sahara image-ID 13 and requests exactly the bytes the MBN header declares
(verified byte-exact: 65,668/65,668, zero padding).

### 3. The boot ROM enforces HTC's signature — proven with a control

* Ten public Firehose programmers (ZTE/OPPO/Xiaomi/Qualcomm reference,
  8974/8974AB/8974Pro/AC) upload successfully, get `END_TRANSFER status=0` and
  `DONE_RSP`, and then the device goes silent and boots after the watchdog.
* A deliberately modified copy of one of them (entry code replaced with a
  marker writer, a watchdog-petting loop, or a USB-controller shutdown) behaves
  identically — no marker ever appears in IMEM.
* **Positive control:** uploading the phone's own **HTC-signed SBL1** makes the
  device drop off the bus **0.28 s** after the upload and boot normally — i.e.
  the ROM authenticates and executes only images signed with the device's key.

So EDL is a dead end without either an HTC-signed programmer or a boot-ROM
exploit.

### 4. eMMC-level write-protect bypass attempts failed

`pg1fs` (partition start LBA 2082, flag sector at LBA 2148) is write-protected.
From Android with root we tried, with raw MMC commands (tool: `edl_tools/mmcwp.c`):

* `CMD29` CLR_WRITE_PROT on the flag's WP group — accepted, no effect.
* `CMD6` write of EXT_CSD[166] (WRITE_PROTECT, reads 0x05) — accepted, ignored.
* `CMD30` SEND_WRITE_PROT — times out (not implemented).
* `CMD24` write of the patched flag sector — "accepted", silently dropped;
  read-back still `03000000`.

This matches the earlier finding that the protection is armed by hboot at boot
(only for boot modes 3 and 0xe) rather than being a card-level WP group.

## The most promising remaining path

hboot skips the eMMC write-protect arming when the boot mode is **not** 3 or
0xe — that is how OTA/recovery writes `/system`. hboot has a table of boot
modes (`androidboot.mode=...`: normal, recovery, recovery_manual, gift_mode,
repartition, power_test, offmode_charging, mfgkernel, 9kramdump*, router modes).

If a mode that still brings up a usable system (or a shell) without arming the
WP can be selected, `pg1fs` becomes writable from that environment and the
S-OFF flag is a 4-byte write.

Concrete next steps:

1. Map the boot-mode table to the numeric modes and find which modes skip the
   arming (the strings live at `0x0F5A0D28`+ in `hboot.img`; the mode item is
   config item #6, read via `f50e7a8`, set through `f50d5ec`).
2. Find what feeds the `name=value` list at hboot RAM `0x0F64D54A+0x65C`
   (it is composed in RAM; the kernel cmdline shows `androidboot.mode=normal`).
3. If recovery mode is WP-free (likely), get a root shell there: stock recovery
   has no USB until a menu item is chosen, so this needs either an OTA path or a
   different recovery.

Alternative path if an HTC-signed image can be obtained (service tools, RUU
leaks, HTC factory firmware): any HTC-signed Firehose programmer for an
8974-family HTC device would immediately give raw flash access.

## Additional analysis done while the phone was parked

* The "boot mode" that hboot compares against 3 / 0xe comes from a field at
  `*(global)+0x15800+0x17C` (getter `f50e7f8`), i.e. it is handed to hboot by
  the SBL in a shared RAM structure rather than read from a partition by
  hboot itself.
* The restart reason (IMEM `0xFE80565C`, defined in
  `mach/htc_restart_handler.h`) **is** read by hboot (`f5346f0` caches it and
  clears the slot). Its values are the HTC restart reasons listed above, which
  makes `androidboot.mode=...` selection and the OEM codes the natural way to
  ask hboot for a different mode.
* hboot's mode list (strings at `0x0F5A0D28` in `hboot.img`) has 18 entries;
  they are referenced without a plain pointer table, so the exact
  name→number mapping still needs to be read out on-device by *observing*
  `androidboot.mode=` after each triggered boot (that is what
  `edl_tools/resume_soff.sh` automates).
* `hboot.img` on the partition is not an MBN (starts `05000000 03000000 ...`,
  load address `0x0F500000` at offset 0x0C), so it cannot simply be served to
  the boot ROM as a Sahara image the way SBL1 can.

## Phone state (important for the morning)

The phone is sitting in HTC's recovery (booted there with `adb reboot
recovery`) — recovery leaves USB down until a menu entry is picked, so it
cannot be reached from the Mac and needs one physical press:

* Power + Volume Up → recovery menu → "reboot system now", **or**
* hold Power ~15 s (screen off) → power on.

Nothing was written to flash: the S-ON flag was re-read after the last write
attempt and still reads `03000000`.

## Tooling left behind

`edl_tools/` — `ensure_root.py` (unattended KingRoot via UI dumps, taps
"TRY TO ROOT"), `s1_firehose.py` (one-window Sahara upload + hand-over and
`soff` action), `try_loader.sh` / `night_loop.sh` (unattended cycles),
`mmcwp.c` (raw eMMC WP/EXT_CSD commands), `usbwatch.py` / `pylusb_watch.py`
(USB event loggers), `kmod/dload` (magics), `kmod/dloadrd` (read-only IMEM
check), plus the earlier `STATE_OF_THE_HUNT.md` and `MODERN_TZ_RESEARCHER_PLAN.md`.

Logs from tonight: `/tmp/edl_run*.log`, `/tmp/soff_*.log`,
`/tmp/night_loop.log`, `/tmp/root_shots/`.
