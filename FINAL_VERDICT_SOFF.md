# Final verdict: software-only S-OFF on this Verizon HTC One (M8)

> **CORRECTION (later the same day): this verdict was wrong.**
> S-OFF *was* achieved in software.  The missing piece was that
> `regulator_force_disable()` on `pm8941_l20` stops at the regulator
> framework's `use_count`; calling the *driver* ops directly (the same thing
> `_regulator_force_disable()` does) really does cut the card's VCC and the
> rail does come back, so the card power-cycles, `PWR_WP` clears, and
> LBA 2148 becomes writable for one window.  That is `kmod/emmcpwr/emmcpwr12.c`
> and it produced `security: off` / `secure_flag: 0`.
> With S-OFF in place the bootloader lock flag was then written directly —
> see **[BOOTLOADER_UNLOCK_FLAG.md](BOOTLOADER_UNLOCK_FLAG.md)** — and the
> device now reports `device unlocked!!` and runs LineageOS 19.1.
> The analysis below is kept as the record of what had been measured up to
> that point.

Date: 2026-09-13 (final session).  Device: HTC6525LVW `HT45FSF02406`, hboot
3.19.0.0000, **LOCKED / S-ON**, Android 5.0.1, temp root via KingRoot.

**Result: no software-only path to S-OFF exists on this device.**  Everything
below was measured on hardware, not inferred.

## What S-OFF actually requires here

The S-OFF flag is the first dword of `pg1fs_security` (LBA 2148), value 3 =
S-ON.  It has no CRC and no signature, so *any* successful write of that sector
is enough - the only problem is that the sector sits inside the eMMC region
that hboot write-protects on **every** boot.

hboot arms that protection with `CMD6 EXT_CSD[171] = PWR_WP_EN` followed by
`CMD28` for groups 0..23 (first 384 MiB), and this is re-armed on every boot
(the five arming clusters are gated on boot command 3/0xe; a normal Android
boot uses 0xe; the misc/BCB route cannot influence it).

`PWR_WP` is a **volatile** card state - per JEDEC it is cleared only by a real
VCC power cycle of the card.  Everything therefore reduces to: get the card to
lose VCC and then write LBA 2148 *before* something re-arms the protection.

## The three ways to get there, and what the hardware did

### 1. Cut the card's supply (pm8941_l20 / RPM LDO20) - one way

`regulator_force_disable("8941_l20")` **does** cut the card: immediately
afterwards the hardware state reads
`/sys/class/regulator/regulator.35/state = disabled`.

`regulator_enable()` afterwards does **not** bring the rail back.  Measured with
the device awake (screen on, `svc power stayon true`, framework running):

```
emmcpwr10: force_disable -> rc=0, enabled=0
emmcpwr10: enable        -> rc=0, enabled=0
emmcpwr10: re-enable try 1..5 -> enabled=0
emmcpwr10: RAIL DID NOT COME BACK
init_module -> 0xffffffd7 (-41)
```

The RPM regulator's enable path is a no-op for this always-on resource, so the
cut is a one-way street inside a boot: the eMMC never comes back, the mmc core
removes `mmcblk0`, `/data` and `/system` die and the phone freezes until reset
(a reset restores the rail, but hboot then re-arms the write protection).

### 2. Brown-out the rail by lowering its voltage - impossible

The DT pins the rail to a single voltage:

```
/sys/class/regulator/regulator.35/min_microvolts = 2950000
/sys/class/regulator/regulator.35/max_microvolts = 2950000
regulator_set_voltage(reg, 1200000, 1200000) -> rc = -22 (EINVAL)
```

No voltage-drop power cycle is available.

### 3. eMMC hardware reset (RST_n) instead of a power cycle - no effect on WP

This kernel has the Reset path backported and it executes cleanly:

```
mmc_hw_reset(host) -> mmc_do_hw_reset(host, 0)
    -> mmc_host_clk_hold, mmc_set_clock(host->f_min)
    -> mmc_power_cycle(host)          [host->ops->hw_reset = sdhci_hw_reset]
    -> host->bus_ops->reset(host)     [card re-enumerated in place]
init_module -> 0
```

The card re-initialises and the block device stays perfectly healthy - but the
protection is untouched:

```
WP type bitmap: 00 00 aa aa aa aa aa aa
  group 0  lba 0..32767  type=2 POWER-ON
CMD24 -> r1=04000900 WP_VIOLATION, write discarded
pg1fs_security = 03 00 00 00 00 00 00 00 01 ...
```

So this card does **not** clear `PWR_WP` on a hardware reset; only an actual
VCC loss does.

## Structural conclusion

The write protection is armed by hboot *before* Android (or anything we
control) starts.  The one event that clears it - a genuine VCC loss at the
card - also makes the card unreachable, and the only software handle on that
rail (`pm8941_l20`) can switch it off but not on again.  There is no reachable
window in which LBA 2148 is writable, which is exactly why this route is
closed rather than merely difficult.

Combined with the previously closed paths - EDL accepting HTC-signed images
only, the HTCdev unlock rejecting this CID/MID (error 172), `oem
writesecureflag` gated on the JavaCard/keycard, the published MSM8974
TrustZone exploit being hardened away, Samsung vendor commands not bypassing
WP, and the trustlets having no path to the eMMC write protection - a
software-only S-OFF on this Verizon M8 is not attainable.

## Reusable results from this hunt

* `mmc_host` layout on this kernel (from `mmc_alloc_host`): `sizeof == 0x600`,
  `class_dev` at **+8**, `host->parent` at +0, `host->index` at +0x198,
  `host->card` at +0x29c, `host->bus_ops` at +0x464, `host->ocr_avail` at
  +0x290.  Walking the `msm_sdcc.1` children and using `dev - 4` yields a
  silently wrong host that panics inside `mmc_suspend_host`/`mmc_detect_change`
  - use `dev - 8` and verify `host->parent` before touching anything.
* `mmc_send_cxd_data` is the template for raw single-block requests:
  `mrq.cmd @+4`, `mrq.data @+8`, `cmd.opcode/arg/flags/error` at
  0/4/0x18/0x20, `data.timeout_ns/blksz/blocks/error/flags/sg_len/sg` at
  0/8/0xc/0x10/0x14/0x24/0x28.
* `mmc_reinit(host)` = claim + `mmc_init_card(host, host->ocr_avail,
  host->card)` + release; `mmc_reinit_card` is the same plus
  `mmc_power_off`/`msleep(100)`/`mmc_power_up` (the block layer's own error
  recovery - it leaves a working card, `mmc_resume_host` alone does not
  because it can skip `mmc_power_up`).
* A suspended host (screen off) makes every re-init fail with -EILSEQ; all
  card work has to happen with the device awake.
* `regulator_force_disable` on an always-on RPM resource is one-way.
* Never let `/data` keep `errors=panic` while doing any of this: remount it
  `errors=continue` first (`mount -o remount,errors=continue /data` works even
  when `remount,ro` returns EBUSY).

Artifacts: `tools/emmcwp.c` (MMC command tool with `type`/`wtest`/`flagread`/
`flagsoff`), `kmod/emmcpwr/` (the suspend/cut/resume/RST_n ladder, ending at
`emmcpwr11.c`), `edl_tools/ensure_root.py` (unattended KingRoot re-root).
