# HTC One (M8) Verizon — software-only S-OFF **and** bootloader unlock

Reverse engineering notes and tooling for the HTC One (M8) Verizon
(`HTC6525LVW`, MID `0P6B20000`, CID `VZW__001`, hboot `3.19.0.0000`,
TZ `TZ.BF.2.0-2.0.0114`), plus everything needed to repeat the result on
another device.

**Result: this phone is S-OFF *and* UNLOCKED, with no HTCdev token, no
keycard, no paid tool and no EDL.**

```
fastboot getvar security            -> security: off
fastboot oem readsecureflag         -> secure_flag: 0
fastboot oem refurbish unlockstatus -> device unlocked!!
TWRP 3.7.0-9 flashed, LineageOS 19.1 (Android 12) installed and booting
```

## Start here

**[`SECOND_DEVICE_HOWTO.md`](SECOND_DEVICE_HOWTO.md)** — the end-to-end
runbook: get root, power-cycle the eMMC to clear its write protection, write
the S-OFF flag, write the lock flag, then flash TWRP and LineageOS. Every
tool it references lives in this repo, and every gotcha (including the
boot-image cmdline trap that breaks recovery) is written down.

**[`METHODOLOGY.md`](METHODOLOGY.md)** — how the route was *found*: the
researcher-playbook phase and why it dead-ended, how hboot was reversed
(PC-relative string xrefs, 2,730 anchors, no decompiler), how "the write is
silently dropped" was measured, and where the power-cycle idea came from
(the vendor's own regulator code, not an exploit write-up).

The short version of what was learned:

* **S-OFF** is dword 0 of the `security` file in `pg1fs` (LBA 2148).  It is
  protected by the card's power-on write protect, which hboot re-arms on
  every boot and which only a genuine VCC power cycle clears.  Cutting that
  rail looks impossible from the regulator API — until you call the
  regulator's *driver* ops directly (`tools/kmod_emmcpwr/emmcpwr12.c`).
* **The bootloader lock** is dword 1 of the same file: `"HTCU"` = unlocked,
  `"HTCL"` = relocked, `0` = locked.  With S-OFF in place hboot no longer
  arms the write protection, so it is a plain 4-byte write.
* hboot appends ~900 bytes of its own text to the kernel cmdline in a
  1024-byte buffer, so boot images with long cmdlines (TWRP, Lineage) kill
  the bootloader — shorten the cmdline to ~25–60 bytes first.

## TrustZone work (the research that came before)

Along the way this repo also documents a working normal-world → TrustZone
client and a full map of the SCM interface, plus a concrete explanation of
why the published `MSM8974_exploit` does not transfer to this HTC build.

## Summary of results

* **Kernel code execution.** A loadable module built from scratch with a
  generic LLVM ARM toolchain: hand-built `struct module`, real symbol CRCs
  pulled from the running kernel's `__kcrctab`, correct vermagic and e_flags.
* **Full TrustZone address map derived offline** by cross-matching HTC's
  `tz` image against the Nexus 5 (hammerhead KTU84P) image. Both are
  `TZ.BF.2.0` builds sharing identical segment virtual addresses, so the
  known Nexus 5 addresses act as a Rosetta Stone.
* **The complete SCM command table** for this build: 67 commands with names,
  handler addresses and flags, recovered from the descriptor table inside
  the TZ image.
* **Register-SCM (`scm_call_atomic*`) invocation solved**, including the
  cache-coherency problem: TrustZone writes to a caller buffer are invisible
  through a cached mapping and require CP15 clean/invalidate around the call.
* **Root cause analysis** of why `laginimaineb/MSM8974_exploit` does not
  transfer — see `FINDINGS.md`.

## Why the published exploit fails here

The exploit bootstraps with a wild zero-write (`SCM_SVC_ES`/`0x2`,
`tzbsp_es_is_activated`) aimed at TrustZone's own bounds-check dword; zeroing
that dword is what disables TrustZone's SCM buffer address validation.

On this build the address validation is live *before* that write, so the
write itself is refused (`0xffffffee`) — chicken and egg. Nexus 5's
`TZ.BF.2.0-2.0.0087` lacks the check; HTC's `2.0.0114` has it.

Measured on-device:

```
es_is_activated(non-secure, 0)  -> 0          (writes 0)
es_is_activated(TZ address, 0)  -> ffffffee   (refused)
prng_getdata(TZ address, 1)     -> ffffffee   (refused)
fver_get_version(0, TZ, 4)      -> ffffffee   (refused)
```

## Contents

| Path | What it is |
|---|---|
| `FINDINGS.md` | Full write-up: method, measurements, dead ends |
| `HANDLER_ANALYSIS.md` | Audit of all analyzable SCM handlers for unchecked length fields |
| `TRUSTLET_ANALYSIS.md` | Widevine trustlet recon: command table, memcpy, and where the audit stopped |
| `htc_symbols.py` | Derived TrustZone address map for this device |
| `kmod/tzmod.c` | Loadable module: SCM client + probes |
| `kmod/tzmeta.c` | Module ELF metadata (`__versions`, `__modinfo`, `__this_module`) |
| `kmod/build.sh` | Build script (clang/LLD → kernel module) |
| `tools/insmod.c` | Direct `init_module(2)` loader (bypasses toybox `insmod`) |
| `tools/rmmod_raw.c` | Direct `delete_module(2)` unloader |
| `tools/refscan.py` | Find references to a TZ address in a dumped image |
| `tools/kernel_extract.py` | Pull the kernel out of an HTC `boot.img` |

## Reproducing

You need:

* Your own dump of the device's `tz` partition (`/dev/block/mmcblk0p9`, 2 MB).
* The Nexus 5 KTU84P factory image for the cross-reference. TrustZone is not a
  separate file in it; it lives inside the `BOOTLDR!` container in
  `bootloader-hammerhead-hhz11k.img`. Container entries are 68 bytes each with
  implicit sequential offsets, and it begins at file offset `0x200`, so the TZ
  ELF is at `0x4c034`.
* An LLVM toolchain with the ARM target and `ld.lld`, plus Python 3 and
  capstone.

Then:

```sh
kmod/build.sh exploit     # builds tzmod.ko with the probe stages enabled
adb push kmod/tzmod.ko /data/local/tmp/tzctl.ko
adb shell 'su 0 /data/local/tmp/insmod_raw'
```

Note: the stock `insmod_raw` on the device ignores `argv`, so the module must
be pushed to its hardcoded path `/data/local/tmp/tzctl.ko`. See
`tools/insmod.c` for a corrected loader.

## What is NOT in this repo

Deliberately excluded: device firmware dumps (`tz.img`, `hboot.img`,
`boot.img`, `recovery.img`, partition dumps), the HTCdev identifier token,
decompressed vendor kernel images, and any personal data. Those are
proprietary vendor blobs or device-unique data and do not belong in a public
repository. Everything needed to *reproduce* the work is code and analysis;
the inputs are described above.

## Status

Both goals are **met**: the device is S-OFF and the bootloader is unlocked,
entirely from software, and it runs LineageOS 19.1.  The TrustZone route was
a dead end on this build (the address validator is hardened), but the eMMC
write-protection route was not: see
[`EMMC_WP_VOLATILE.md`](EMMC_WP_VOLATILE.md),
[`SOFF_FLAG.md`](SOFF_FLAG.md) and
[`BOOTLOADER_UNLOCK_FLAG.md`](BOOTLOADER_UNLOCK_FLAG.md).

`FINAL_VERDICT_SOFF.md` is kept as the record of the intermediate negative
result; it carries a correction at the top explaining exactly which
assumption was wrong.
