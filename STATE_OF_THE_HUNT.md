# State of the hunt — unlocking a Verizon HTC One (M8), software only

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

## Tools in this repo that made it possible

`tools/xref2.py` (drift-free PC-relative string xrefs, 2730 refs),
`tools/xrefs.py` (verified single-target xref), `tools/blrefs.py` (call
graph), `tools/dump.py` (annotated Thumb disassembly), `tools/strrefs.py`,
`tools/wpmap.py` (AP-write protection map), plus the on-device tools
`mmcprobe`, `mmcrw`, `blkio`, `atsctl` and the kmod build recipe.
