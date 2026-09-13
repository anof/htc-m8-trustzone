# What modern Qualcomm-TrustZone researchers would do with this device

Device recap: HTC One (M8) `m8_wlv` / `HTC6525LVW`, MSM8974, hboot 3.19.0.0000,
TZ `TZ.BF.2.0-2.0.0114` (2016 build), Android 5.0.1, S-ON, LOCKED,
root via KingRoot (temporary), `/dev/qseecom` reachable from apps.

Written from the standpoint of the people who actually do this for a living
(Beniamini/P0, Quarkslab, Check Point's QTEE fuzzing line, Blue Frost,
Keen Lab, NCC, `bkerler`) — i.e. *what they would try first, and why* —
contrasted with what this project already proved by measurement.

## The order they would work in

1. **Fuse / Secure-Boot triage + EDL (cheap, and it can end the whole
   problem in one step).**
   Read the QFPROM security fuses and test whether the device's **PBL
   accepts an unsigned Firehose programmer in EDL (USB 9008)**. Rationale:
   if programmer authentication is not enforced, you don't need any exploit
   at all — Firehose writes raw eMMC by LBA, so `pg1fs_security` (the S-OFF
   dword) gets flipped in minutes, with no signature involved.
   * Our current evidence: `oem checkHWSecurity` reports
   *"HW Security has been enabled !"* (reads a QFPROM register at
   `0xFC4B83F8`, bit 5) and the kernel cmdline carries
   `androidboot.efuse_info=NL`. Ambiguous — must be tested, not assumed.
   * Entry points to EDL that exist in this hboot: the OEM command
   `to_sbldload` (chipset_security group, string `0x0f5aed36`; its handler
   table sits at `0x0f6604a0`+, handlers in `0x0f53c5xx`-`0x0f53c9xx`),
   alongside `ddr2gbh`, `ramdump2gbh`, `enableqxdm`, `gencheckpt`,
   `validateimeihash`. Hardware key-combo entry is the fallback.
   * Tooling: `bkerler/edl` (or a small Sahara client) on the Mac + a
     Firehose programmer for MSM8974. If Secure Boot is fused, only an
     HTC-signed programmer works; if not, any compatible
     `prog_emmc_firehose_8974.mbn` will do.
   * Caveat: EDL is sticky — a failed attempt leaves the phone in 9008
     until it is power-cycled by hand.

2. **Enumerate and fuzz the reachable QSEE trustlets (Check Point's method).**
   `/dev/qseecom` on Android 5.0.1 is open to any process (we verified: the
   KeyMaster CVE-2016-5349 PoC runs). So the attack surface is every TA in
   `tz.img` (widevine, keymaster, cmnlib, playready, dxhdcp2, prov, …) and
   its **command handlers**, not its crypto. Fuzz command IDs and argument
   lengths; look for memory corruption inside TZ.

3. **Diff against other MSM8974 TZ builds to find "fixed later ⇒ vulnerable
   here" bugs.** Our TZ is a 2016 build; anything CVE'd in 2017+ whose code
   is still present is fair game. We already hold both sides of such a diff
   (`htc_tz.bin` vs the Nexus 5 `n5_tz.img`). The diff also shows exactly
   where HTC added the SCM address validation that defeated the published
   MSM8974 exploit.

4. **Insist on a *write* primitive, not a leak.** Our measurements show the
   address validator, the XPU and the eMMC WP all stop the AP cold. So a
   read-only TZ bug (e.g. CVE-2016-5349, which works here but reads zeros
   from secure ranges) is useless for the goal; the bug must give arbitrary
   **write** in the secure world to (a) flip `pg1fs_security`, (b) re-point
   the XPU windows, or (c) drive hboot's own flash routine.

5. **Chain to the goal**: with TZ write, patch the S-OFF dword in
   `pg1fs_security`, or patch `board_info` (CID/MID) and walk the normal
   unlock path.

## What they would *not* spend time on (and we proved why)

* **hboot code itself** — small, signature-centric; its flash verifier is
  local SHA-1+RSA but the *boot-time* boot/recovery check is TZ-backed, so
  a hboot bug alone yields an unbootable image. (`f528648`→`f52ab08`
  hashes, `0x0f514276` → SMC verifies.)
* **CID games / HTCdev** — the local gate is a string compare, but the
  unlock token is RSA-signed and HTCdev's model rule blocks this MID.
* **Any "boot in a special mode so the AP can write" idea** — hboot only
  ever *arms* the eMMC write-protect (`partition_write_prot_mmc`, 25 call
  sites, all `r2 = 1`); nothing clears it, so skipping the arm changes
  nothing on an already-protected device.

## The evidential reason to take the TZ route seriously

**Firewater and SunShine both S-OFF'd this exact phone and firmware with
software-only TZ exploits**, and SunShine explicitly lists the Verizon M8 on
4.17.605.17 — i.e. a working TZ bug for `TZ.BF.2.0-2.0.0114` provably
exists. Highest-confidence path: work backwards from that (recover or
reconstruct SunShine's payload, or identify which bug it used) rather than
fuzzing blind.

## Who to follow / whose methods these are

Beniamini (`laginimaineb`, P0), Sean Beaupre (`beaups`, Atredis — HTC
safezone + Firewater/SunShine), `jcase`, Dan Rosenberg, Di Shen
(Keen Lab), Ning Zhenyu (Nailgun), Quarkslab (Peterlin/Adamski/Aumaitre),
Check Point's QTEE fuzzing line (`bferrite`), Andrey Akimov, Blue Frost
(Eloi Sanfelix), `bkerler` (Qualcomm TZ/Secure-Boot + EDL tooling), NCC
Group (keystore), `LimitedResults` (fuse/Secure Boot), and the
`enovella/TEE-reversing` index for the paper trail.
