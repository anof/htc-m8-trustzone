# The S-OFF flag is not sealed: hboot's lock is the card's *write-protect
# groups*, and those are set/cleared by ordinary MMC commands from the AP

Date: 2026-09-13 (offline session, phone unplugged). Device: HTC One (M8)
Verizon `HT45FSF02406`, hboot 3.19.0.0000, S-ON, CID `VZW__001`,
Android 5.0.1, firmware 4.17.605.17, temporary root via KingRoot.

This supersedes the "hardware write-protect (hboot arms it each boot via
`msm_mpu_emmc_protect`)" line in earlier notes. That description was right
about the *who* and wrong about the *how*, and the difference decides
whether software-only S-OFF is possible. It is.

---

## 1. What actually blocks the write

`partition_write_prot_mmc(start,end,mode)` (`0x0f504a30`) does **not** touch
SoC registers. Read end to end it is:

```
start_lba = partition_lookup(start)                 ; f50410c
end_lba   = partition_lookup(end) + size(end)       ; f5041b4
if (emmc_init())                       -> "eMMC initial fail"
grp = driver_op8(&{cmd:8})                          ; op 8 = FW_WP_GRP_SIZE_INFO
if (grp <= 0)                          -> "eMMC FW_WP_GRP_SIZE_INFO fail"
{lba,mode,2} -> driver_op9(&{cmd:9,...})            ; op 9 = FW_SET_WRITE_PROT_GROUP
for (lba = start_lba; lba < end_lba; lba += grp)
        driver_op9(&{cmd:9, table:{lba, mode}, count:2})
```

So it is a **loop over write-protect groups, issuing one command per group**,
and `mode` (the caller's third argument) is the *protect/unprotect* flag that
is handed to the card. That is exactly the shape of Qualcomm's `mmc_boot_*`
code that still ships in open LK trees — `platform/msm_shared/mmc.c`:

```c
	/* wp_group_size = 512KB * HC_WP_GRP_SIZE * HC_ERASE_GRP_SIZE */
	wp_group_size = (512 * 1024) * ext_csd_buf[MMC_BOOT_EXT_HC_WP_GRP_SIZE] *
			ext_csd_buf[MMC_BOOT_EXT_HC_ERASE_GRP_SIZE] / 512;

	/* Setting POWER_ON_WP for USER AREA (CMD6) */
	mmc_boot_switch_cmd(card, MMC_BOOT_SET_BIT, MMC_BOOT_EXT_USER_WP,
			    MMC_BOOT_US_PWR_WP_EN);

	if (set_clear_wp) cmd.cmd_index = CMD28_SET_WRITE_PROTECT;
	else              cmd.cmd_index = CMD29_CLEAR_WRITE_PROTECT;
	for (i = 0; i < loop_count; i++) { cmd.argument = addr + i*wp_group_size; ... }
```

(`wp_grpsize: %d`, `wp_grpen: %d`, `EXT_CSD ERASE_GRP_DEF = 0x%02X`,
`EMMC_WP_MAGIC_2 type:%X` are *all* present in our hboot image — same code
lineage.)

The protection therefore lives in the **eMMC's own write-protect groups**,
programmed with SET_WRITE_PROT (CMD28), reported with SEND_WRITE_PROT (CMD30)
and SEND_WRITE_PROT_TYPE (CMD31), and cleared with CLEAR_WRITE_PROT (CMD29).
A card that is write-protected in a group **accepts** a write to that group
and discards the data — which is exactly the "pwrite returns 16 bytes, read
back is unchanged" behaviour measured earlier.

## 2. What type of protection is armed here — measured from the card

`/tmp/extcsd.bin` (EXT_CSD read on 2026-09-13 03:58) says:

| EXT_CSD byte | value | meaning |
|---|---|---|
| 192 `EXT_CSD_REV` | 6 | eMMC 4.5 |
| 212 `SEC_COUNT` | 61071360 | 29.1 GiB user area (32 GB part) |
| 175 `ERASE_GROUP_DEF` | 1 | high-capacity group definition in use |
| **221 `HC_WP_GRP_SIZE`** | **32** | |
| **224 `HC_ERASE_GRP_SIZE`** | **1** | ⇒ **wp_group_size = 16 MiB (32768 sectors)** |
| **171 `USER_WP`** | **0x00** | PWR_WP_EN=0, PERM_WP_EN=0 |
| 173/174 `BOOT_WP`/`BOOT_WP_STATUS` | 0x00 | boot areas not protected |

and the WP *type* set by CMD28 is selected by `USER_WP`
(from the open Huawei/MTK driver `emmc_system_wp.c`):

```
 * US_PERM_WP_EN   US_PWR_WP_EN   Type of protection set by SET_WRITE_PROT
 *            0              0   Temporary
 *            0              1   Power-On
 *            1              x   Permanent
```

`USER_WP = 0x00` ⇒ every group hboot armed is **Temporary** type, which
(a) CMD29 clears and (b) a genuine power cycle clears. Also, hboot's own
source sets `PWR_WP_EN` *before* arming — our card reads 0x00, i.e. that
step was never done on this unit, so the classification is Temporary, not
Power-On and not Permanent.

Public corroboration that this is the known, exploitable configuration:
**CVE-2014-9961** — "*In all Android releases from CAF using the Linux
kernel, a vulnerability in eMMC write protection exists that can be used to
bypass power-on write protection*" (Android bulletin 2017-06).

## 3. Why previous attempts failed (all three are tool bugs, not walls)

1. They used **CMD28/CMD29 on the wrong premise** — no WP *type* read
   (CMD31) was ever taken, so "temporary" vs "power-on" vs "permanent" was
   never known. The type is the single measurement that decides the whole
   route.
2. The EXT_CSD experiment wrote **byte 166** (`WR_REL_PARAM`, write
   reliability) instead of **byte 171** (`USER_WP`).
3. The R1 status word from CMD24/CMD29 was never decoded. A card that
   rejects a write to a protected group returns `WP_VIOLATION` (bit 26) —
   "the write went missing" and "the card refused the write" are different
   measurements, and only the first was taken.

## 4. The flag itself needs no integrity work

`pg1fs_security` (partition offset 0x8400, absolute LBA 2148) on this device
reads:

```
03 00 00 00 | 00 00 00 00 | 01 00 00 00 | 00 00 00 00 ...
```

Only offsets 0 (`security_level`, 3 = S-ON) and 8 (`jtag_disable_flag`) are
non-zero; the CRC32 field (0x504) and the 256-byte section-1 signature
(0x400) are **zero**. hboot's only writer (`f531898`) just stores the dword
and writes the 0x1000-byte file back. So flipping S-ON→S-OFF is a 4-byte
change to the *first dword of one sector* — no checksum, no signature, and
`read_secure_flag() <= 1` is by itself the S-OFF condition (`f50e7a8`).

The group that must be unprotected is group **0** (LBAs 0..32767), which
also contains the primary GPT and `sbl1` — so the operation is done as
*unprotect group 0 → write LBA 2148 → re-arm CMD28 on group 0*.

## 5. The tool: `emmcwp`

`emmcwp.c` (built by `build_emmcwp.sh` against the phone's own bionic libc,
pushed to `/data/local/tmp/emmcwp`) talks to `/dev/block/mmcblk0` with
`MMC_IOC_CMD`, and for **every** command prints the R1 status word decoded
(`ADDR_OUT_OF_RANGE`, `WP_VIOLATION`, `WP_ERASE_SKIP`, `SWITCH_ERROR`,
current state).

| mode | what it does |
|---|---|
| `info` | EXT_CSD: USER_WP, BOOT_WP, group size, save to `/data/local/tmp/extcsd_now.bin` |
| `type <lba> [n]` | **CMD31** — WP type (none/temporary/power-on/permanent) of each group |
| `wp <lba>` | CMD30 — WP bits |
| `clr <lba>` / `set <lba>` | CMD29 / CMD28 |
| `usrwp <mode> <val>` | CMD6 on EXT_CSD[171] (0=write, 1=set bits, 2=clear bits) |
| `wtest <lba>` | read → write `orig^0xA5` → read back → restore; *proves* writability |
| `flagread` / `flagsoff` | read LBA 2148 / back it up to `/data/local/tmp/security_lba_backup.bin`, write 0, verify byte-for-byte |
| `seq` | the whole non-destructive diagnosis and, if it clears, the flag write + WP re-arm |
| `unprotect <lba>` | CMD29 → (if needed) clear `USER_WP` enable bits → CMD29 → re-test |

Scratch LBA for the write test is **4130** = `pg1fs + 1 MiB`: the partition
is 119 MB and its last non-zero byte is at offset 0xB000, so that sector is
provably unused, and it is in the *same 16 MiB group* as the flag, so a
successful scratch write is a faithful test of the flag's group.

## 6. Sequence to run when the phone is back (automated: `soff_run.sh`)

```
adb push emmcwp /data/local/tmp/ ; su -c 'chmod 755 /data/local/tmp/emmcwp'
su -c '/data/local/tmp/emmcwp seq'          # prints everything, writes the flag if it can
# if still protected:
su -c '/data/local/tmp/emmcwp unprotect 2148'
su -c '/data/local/tmp/emmcwp flagsoff'
su -c '/data/local/tmp/emmcwp set 0'        # put the WP back
```

Verdict is read back from the card (`security_level = 0`) and then from the
bootloader (`fastboot oem readsecureflag` → `secure_flag: 0`, and the
`S-OFF` banner).

## 7. If it works — the rest of the plan

S-OFF is the whole gate. With `security <= 1` hboot stops treating the
boot/recovery/system signatures as authoritative, so:

1. `fastboot flash recovery twrp-…-m8.img` (unsigned is now accepted),
2. boot TWRP, `adb sideload`/install **LineageOS** for `m8` (AOSP boot
   image, its own kernel), then GApps/whatever,
3. optional cleanup with S-OFF: `fastboot oem writecid 11111111` (superCID),
   `fastboot oem lock`/unlock as desired, restore the WP state.

## 8. If it does not work

`emmcwp type` returning **3 (permanent)** for group 0 means the card was
programmed with permanent WP and *no* AP-side write is possible; the log
then decides between (a) Power-On type with `USER_WP` still set (clear the
enable bits, retry), or (b) the SoC/XPU being the enforcer after all — which
would put the TZ route back on the table. The R1 word and the CMD31 bitmap
in the log distinguish these cases unambiguously, which is the point of the
tool.
