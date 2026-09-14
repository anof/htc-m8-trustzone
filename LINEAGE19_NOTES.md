# LineageOS 19.1 on the M8: modem crashes, GApps, and the fixes

Follow-up work after the unlock, on the same device (S-OFF + unlocked,
firmware `4.17.605.17`, baseband `1.12.20.1211`, LineageOS 19.1
`19.1-20220825-UNOFFICIAL-m8`, Android 12 / SDK 32).

## 1. "The modem keeps crashing"

The kernel log from the previous boot (`/proc/last_kmsg`) showed the real
cause:

```
SMSM: Modem SMSM state changed to SMSM_RESET
Fatal error on the modem
modem subsystem failure reason: FW@lte_LL1_vpe_schdr_dl.c:2035 Assertion
    (diff_univ_stmr_cnt >= LTE_LL1_WAKEUP_...)
subsys-restart: subsystem_restart_dev(): Restart sequence requested for modem,
    restart_level = SYSTEM
Kernel panic - not syncing: subsys-restart: Resetting the SoC - modem crashed
set_restart_msg = KP: subsys-restart: Resetting the SoC - modem crashed.
```

So the *modem firmware itself* asserts in its LTE low-level stack, and because
the modem subsystem's restart level is `SYSTEM`, the kernel panics and reboots
the whole phone.  Root cause is the usual one: a 2022 Android 12 ROM driving
the 2015 Lollipop-era modem firmware.  The proper fix is updating the firmware
to the last Verizon Marshmallow release (the `6.21.605.3` RUU); that also
updates `rpm`/`tz`/`sbl1`/`radio`.

### Mitigation used here (no firmware needed)

The kernel exposes the restart level per subsystem:

```
/sys/devices/fc880000.qcom,mss/subsys1/restart_level   # "SYSTEM"
/sys/devices/fb21b000.qcom,pronto/subsys2/restart_level # "RELATED" (wifi)
```

Writing `RELATED` there makes a modem crash restart only the modem instead of
panicking the SoC.  The node is root-only and only exists after the modem
platform device probes, so it is written from `init.rc` at boot.  On this ROM
`init.rc` lives in the **system** image (`/system/etc/init/hw/init.rc`, a
system-as-root-less legacy layout), so the line was appended there from TWRP:

```
on boot
    write /sys/devices/fc880000.qcom,mss/subsys1/restart_level RELATED
```

Verified after reboot: `cat ...restart_level` -> `RELATED`.

Note the ROM's boot ramdisk contains **no** `default.prop`/`init.rc` (only
`init`, `system/etc/ramdisk/build.prop`, mount points), so boot-image ramdisk
edits cannot change `ro.secure` or add init commands on this build — the
system partition is the right place.

## 2. Google Play on this ROM

LineageOS ships no Google apps (licensing), so they were installed from
**MindTheGapps 12.1.0 arm** (`MindTheGapps-12.1.0-arm.zip`, SDK 32,
arch `armv7l`).

### Why the stock installer fails here

MindTheGapps' `update-binary` locates partitions through TWRP's
`/etc/recovery.fstab`:

```
get_block_for_mount_point() {
  grep -v "^#" /etc/recovery.fstab | grep "[[:blank:]]$1[[:blank:]]" \
    | tail -n1 | tr -s [:blank:] ' ' | cut -d' ' -f1
}
```

This TWRP fstab is in the old `mountpoint fstype device` format, so the grep
never matches and the helper returns an empty device:

```
mount: : need -t
Error installing zip file '/sdcard/gapps.zip'
```

The package also assumes the mounted system image has a `system/` subdirectory
(`SYSTEM_OUT="${SYSTEM_MNT}/system"`), which is not this ROM's layout.

### What was done instead

The payload was copied in by hand from TWRP, replicating what the installer
does after mounting: extract `system/*`, set directories `0755`, files
`0644` (scripts `0755`), owner `root:root`, SELinux context
`u:object_r:system_file:s0`, then `cp -a system/. /system/`.

Verified afterwards:

```
package:com.android.vending            (Play Store)
package:com.google.android.gms         (Play Services)
package:com.google.android.gsf         (Services Framework)
package:com.google.android.setupwizard
```

## 3. Root adbd without the UI toggle

Lineage 19.1 has no `su`, and `adb root` answers "ADB Root access is disabled
by system setting - enable in Settings -> System -> Developer options"
(`persist.sys.*` cannot be set from a shell).  Instead `ro.secure=1` and
`ro.adb.secure=1` were flipped to `0` in `/system/build.prop` from TWRP, which
makes adbd start as root:

```
adb shell id -> uid=0(root) ... context=u:r:su:s0
```

## 4. NFC crash loop

`com.android.nfc` was restarting about once a second:

```
Fatal signal 11 (SIGSEGV) ... in tid (com.android.nfc)
#00 libnfc-nci.so (NfcAdaptation::InitializeHalDeviceContext()+1068)
```

That is the same old-firmware/new-ROM class of problem (NFC firmware/HAL
mismatch) and it burned CPU on an idle device.  The device only needs Wi-Fi,
so the package was disabled:

```
pm disable-user --user 0 com.android.nfc   -> disabled-user
```

## 5. State after this work

* LineageOS 19.1 (Android 12) boots, Play Store + Play Services + GSF present.
* `uid=0` over adb.
* Modem crashes restart the modem, not the phone.
* Still open: updating firmware to `6.21.605.3` would fix the modem assert at
  the source and likely the NFC HAL too; the files for that are not in this
  repo (HTC-signed RUU, not redistributable).
