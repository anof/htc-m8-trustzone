# The bootloader lock flag — located, decoded, and unlocked

Date: 2026-09-13 (final session). Device: HTC One (M8) Verizon
`HT45FSF02406`, hboot 3.19.0.0000, **S-OFF** (from the earlier session),
firmware 4.17.605.17.

**Result: the bootloader is now UNLOCKED (`fastboot oem refurbish
unlockstatus` -> `device unlocked!!`), done entirely from software.**

This closes the loop on the second flag: S-OFF lives in dword 0 of
`pg1fs_security`, and the **lock state lives in dword 1 of the same file
(LBA 2148, byte offset 4)**.

---

## 1. The flag, from hboot's own code

The single writer of the lock state is `f52faa0(value)`:

```
0f52faa0  ldr  r4, =&g_security_buf      ; 0x0F6A61F4
0f52faa6  ldr  r2, [r4]                  ; the pg1fs_security buffer
0f52faa8  cbz  r2, ret
0f52faaa  str  r0, [r2, #4]              ; <-- dword 1 = lock state
0f52faae  ldr  r0, = "pg1fs_security"
0f52fab0  mov.w r3, #0x1000
0f52fab6  bl   0xf504ee4                 ; write_file(name, 0, buf, 0x1000)
0f52faba  ...
0f52fac0  bl   0xf505214                 ; free buffer
```

The reader is `f52fad8()` (`return *(u32 *)(*0x0F6A61F4 + 4);`), and
`f5355cc()` is the predicate `value == "HTCU"`.

The three legal values are set by `f535778(mode)` and are printed by the
routine at `0x0f5301dc`, which is what names them:

| mode (r0) | stored dword 1 | string it prints |
|---|---|---|
| `1`  | `0x55435448` (`"HTCU"`) | `bl unlock`   |
| `0`  | `0x4c435448` (`"HTCL"`) | `bl relock`   |
| `-1` | `0`                     | `bl lock`     |

Everything else decodes as LOCKED, so a wrong value fails safe rather than
bricking anything.  The banner in the bootloader UI is selected by the same
state: `f5030b8(3)` -> nonzero prints `*** UNLOCKED ***`, and
`fastboot oem refurbish unlockstatus` prints `device unlocked!!` from the
identical call (`0x0f5157fa`).

The field has no CRC and no signature: `pg1fs_security`'s CRC field (0x504)
and section-1 signature (0x400) are both zero, and hboot's writer stores the
dword and rewrites the 0x1000-byte file.

## 2. Why the write was possible at all: S-OFF disarms the eMMC WP

The S-OFF write (earlier session) needed a real card power cycle to clear
`PWR_WP`.  That is not needed for the unlock flag, because **once the device
is S-OFF hboot no longer arms the write protection**:

```
# on the S-OFF device, from Android
emmcwp type 0 1
  WP type bitmap: 00 00 00 00 00 00 00 00
  group 0  lba 0..32767  type=0 none
emmcwp wtest 4130
  => WRITE LANDED (group unprotected)
```

With group 0 writable, the flag is a plain single-sector write.

## 3. The write

`emmcwp flagunlock` (new mode added to `tools/emmcwp.c`) reads LBA 2148,
refuses if the sector does not look like `pg1fs_security` (it requires
`security_level <= 1`, `jtag_disable == 1`, zero tail), backs the sector up
to `/data/local/tmp/security_lba_pre_unlock.bin`, writes `"HTCU"` into bytes
4..7, and verifies byte-for-byte:

```
before: security_level=0 unlock=0x00000000 jtag_dis=1
CMD24 write UNLOCK tag -> r1=00000900 (TRAN)
unlock tag now = 0x55435448 (HTCU / UNLOCKED)
```

After a reboot hboot reports:

```
fastboot oem refurbish unlockstatus
  (bootloader) device unlocked!!
fastboot getvar security
  security: off
```

## 4. What unlocking changed

* `fastboot flash <partition>` is accepted (while LOCKED every target
  answered `not allowed`; RUU zips were the only write path).
* TWRP 3.7.0-9 can be flashed and boots (`fastboot flash recovery`).
* LineageOS 19.1 (Android 12) then installs normally from TWRP.

## 5. The cmdline trap (do not forget this)

hboot builds the kernel command line by appending its own ~900-byte
debug string, into a 1024-byte buffer.  An image whose own cmdline is long
overflows that buffer and hboot dies with an "hboot exception" (this is what
made every TWRP/Lineage attempt fail earlier).  Keep the cmdline in the boot
header short — `androidboot.hardware=qcom` (25 bytes) is proven, and
`androidboot.hardware=qcom androidboot.selinux=permissive` (56 bytes) also
boots.  The kernel/ramdisk are otherwise untouched.

## 6. Artifacts from this session

| file | what it is |
|---|---|
| `tools/emmcwp.c` | `flagunlock` mode (writes `"HTCU"` at LBA 2148+4) |
| `tools/build_root_boot.py` | patches `ro.secure`/`ro.adb.secure` in a boot ramdisk, rebuilds the image |
| `lin141/fw/boot_root.img` | Lineage 14.1 boot with root adbd (`ro.secure=0`) |
| `lin141/fw/boot_root_fw.zip` | RUU zip carrying it (flashed from LOCKED via RUU mode) |
| `twrp/twrp370_cmdline25.img` | TWRP 3.7.0-9 with a 25-byte cmdline |
| `lineage/boot19_patched.img` | Lineage 19.1 boot, 56-byte cmdline |
| `backup_part/pg1fs_pre_unlock.img` | full pg1fs image before the unlock write |
| `pg1fs.img` | full pg1fs image before S-OFF (differs by exactly one byte) |

## 7. Relationship to the other paths

The `flash unlocktoken` route is closed for this device twice over: the
`"VZW__001"` CID gate (`0x0f503590`) and an RSA-2048 token check over a
device-specific 61-byte plaintext.  Editing the flag directly bypasses both
because hboot only ever reads dword 1 of `pg1fs_security` back.
