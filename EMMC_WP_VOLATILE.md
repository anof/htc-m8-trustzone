# The eMMC write protection is *volatile* - and how to clear it from Android

Date: 2026-09-13 (evening session).  Device: HTC One (M8) Verizon
`HT45FSF02406`, hboot 3.19.0.0000, S-ON, Android 5.0.1, temp root via
KingRoot.  This supersedes the "the card's power-on WP cannot be cleared by
the host" conclusion in `EMMC_WP_BYPASS.md`.

## 1. Proof that the protection is volatile

The protected state is **not** a factory fuse; it is armed by hboot on every
boot and it does not survive a power cycle.

Measured:

1. Group 24 (LBA 786432, the `misc` partition) reads `type 0 none` and is
   writable (`wtest` lands).
2. Arming it exactly the way hboot does -
   `CMD6 EXT_CSD[171] = PWR_WP_EN` then `CMD28` on that LBA - flips it to
   `type 2 POWER-ON` and the next write is rejected with `WP_VIOLATION`.
3. After a reboot that group reads `type 0 none` again and writes land,
   while group 0 (the firmware area, where the S-OFF flag lives) reads
   `type 2 POWER-ON` again - i.e. **hboot re-armed its own ranges**.

So the flag is writable in any boot in which hboot does not arm the
protection, or in the window after the card's supply has been cycled and
before hboot runs again.

## 2. What hboot arms, and when

All five `partition_write_prot_mmc()` call clusters are gated on the boot
command (`0x0f50e7f8`) being **3 or 0xe**:

| cluster | gate |
|---|---|
| `0xf56aa7a`, `0xf56d21a`, `0xf56f7fe`, `0xf57209a`, `0xf574956` | `cmp r0,#3` / `cmp r0,#0xe` |

A normal Android boot uses the fallback command **0xe**, so the WP is always
armed before Android starts.  The boot command is read from the runtime
config block (`config+0x1597C`), which is built from write-protected
sources; the `misc` partition (`misc+0`, `misc+0x800`, `misc+0x1000` with a
0x1000 stride, and eight further offsets) was tested with `Reboot` /
`RebootATS` strings and never influenced it - that route is closed.

## 3. Why a suspend does not clear it

`msm8974-m8-common.dtsi` says:

```
&sdhc_1 {                       /* the eMMC */
        vdd-supply = <&pm8941_l20>;
        qcom,vdd-always-on;
        qcom,vdd-lpm-sup;
        ...
};
```

`vdd-always-on` means `msmsdcc_vreg_disable()` only switches the regulator to
low-power mode instead of disabling it, so `mmc_suspend_host()` ->
`mmc_power_off()` leaves VCC on.  Confirmed live: a suspend/resume cycle
leaves group 0 `type 2 POWER-ON` and writes still rejected.

## 4. Why an MMC "rescan" does not re-initialise the card either

`mmc_rescan()` in this kernel returns early when the host still has bus
operations:

```c
        if (host->bus_ops && host->bus_ops->detect && !host->bus_dead
            && !(host->caps & MMC_CAP_NONREMOVABLE))
                host->bus_ops->detect(host);
        ...
        if (host->bus_ops != NULL) {
                mmc_bus_put(host);
                goto out;                 /* <- the eMMC takes this path */
        }
        ... mmc_rescan_try_freq(host, host->f_min);   /* never reached */
```

The M8's eMMC is `qcom,nonremovable`, so `mmc_detect_change()` is a no-op and
the card stays in its idle state after a power cut.  That is why the earlier
attempts left the device writing to a dead card (I/O errors, then a
watchdog reset).

## 5. The correct chain

```
mmc_suspend_host(host)          /* quiesce + POWER_OFF_NOTIFICATION */
regulator_force_disable(pm8941_l20)   /* the actual VCC cut */
regulator_enable(pm8941_l20)
mmc_resume_host(host)           /* mmc_resume() -> mmc_init_card() */
```

`mmc_resume()` calls `mmc_init_card()`, so the card is fully re-enumerated
(CMD0/CMD1/CMD2/CMD3/CMD9/CMD7/CMD8) after the supply returns.

Two practical hazards, both encountered:

* `mmc_stop_bkops()` inside `mmc_suspend_host()` can block while the card runs
  background GC (this eMMC has `htc,bkops_support`).  Disable it first with a
  raw `CMD6` write of `EXT_CSD[163] = 0` (`emmcwp sw 163 0`).
* **Never `FIFREEZE` `/data` for this.**  A FIFREEZE that cannot complete
  leaves the superblock frozen indefinitely, which wedges KingRoot's `su`
  daemon and blocks even `sync()`, so `adb reboot` hangs: the phone then
  needs a 15 s power-button reset.  Remount read-only instead
  (`mount -o remount,ro /data`), which flushes and then rejects writes at the
  VFS without holding the freeze lock.

## 6. Tooling (all working on the device)

* `emmcwp` - MMC_IOC_CMD tool: EXT_CSD decode, `CMD31` WP-type readout,
  `CMD28/29/30`, `CMD6` byte/set/clear (`sw <byte> <val>`), `wtest`
  (write/verify/restore on a scratch LBA), `flagread` / `flagsoff` (writes
  `pg1fs_security[0] = 0` after verifying the sector really is that file).
* `insmod_mmap` - loads a `.ko` by `mmap()`ing it.  The stock `insmod_raw` on
  the device is hardcoded to `/data/local/tmp/tzctl.ko` **and** truncates
  reads at 2968 bytes, so it silently loaded the wrong module; this loader
  takes a path argument and reads the real size.
* `kmod/emmcpwr/emmcpwr2.c` - the suspend -> VCC-cut -> resume module.  It
  resolves `mmc_suspend_host` / `mmc_resume_host` through
  `kallsyms_lookup_name()` (both are exported), finds the mmc0 host by
  walking the `msm_sdcc.1` platform device's children (the class device's
  name is the kobject name at `dev+8`; `dev_name()` is an inline and so has
  no symbol), and refuses to cut power unless everything resolved.  Return
  codes: 0 ok, -20 no suspend/resume primitives, -21 no platform device,
  -22 no mmc0 child, -23 no regulator, -24 suspend failed, -25 resume failed.
* `soff_run2.sh` - the end-to-end runner: push tools, disable BKOPS, remount
  `/data` and `/cache` read-only, load the module, verify the WP type, write
  the flag, restore rw mounts.

## 7. Reading kernel output when logd has drained dmesg

`dmesg` on this device only shows whatever logd has not consumed.  The
previous boot's full kernel log survives in **`/proc/last_kmsg`** (ram
console, 384 KB) - that is how the module's `printk` output and the missing
`Kernel panic` line were read, which is what showed the earlier failures were
hangs (watchdog reset), not panics.
