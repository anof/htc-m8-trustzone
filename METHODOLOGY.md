# Methodology: how the S-OFF + unlock route was actually found

This is the reasoning trail, not the results.  The result documents
(`SOFF_FLAG.md`, `BOOTLOADER_UNLOCK_FLAG.md`, `EMMC_WP_*.md`) say *what* is
true; this one says *how it was arrived at* — including the wrong turn that
produced a written "this is impossible" verdict which had to be overturned
the same day.

The short version:

* **Phase 1** was the playbook you would expect: list the field's leading
  researchers, port their methods.  It produced capabilities and a set of
  *proven* dead ends, but no S-OFF.
* **Phase 2** was reading HTC's own bootloader for an unrelated reason
  (hunting an unlock/flash weakness).  That is what accidentally located the
  S-OFF flag and, more importantly, what actually protects it.
* **Phase 3** was refusing the label "hardware protection" and asking instead:
  *what is armed, when, by whom, and what clears it?*  That reframing turned a
  security problem into a power-management problem — and made the device
  hackable with its own driver code.

---

## 1. Phase 1 — the researcher playbook (capability, and closure)

Starting point: HTCdev refuses this model (`Error Code: 172, CID Not
Allowed`), so unlock had to be produced locally, and the assumption was that
S-OFF was the gate.

Routes pulled from published work:

| route | source | outcome |
|---|---|---|
| MSM8974 TrustZone exploit | `laginimaineb/MSM8974_exploit` | **dead** — HTC's `TZ.BF.2.0-2.0.0114` validates SCM target addresses *before* the bounds-check dword can be zeroed; every secure target returns `0xffffffee` |
| keymaster trustlet bug | CVE-2016-5349 | **dead** — reachable trustlet has no path to the eMMC |
| EDL / Firehose | Qualcomm Sahara | **dead** — EDL *was* entered (magic triple into IMEM from a module) and Sahara completed, but the boot ROM only executes HTC-signed images (proven with a positive control: the phone's own signed SBL1 runs, ten public programmers do not) |
| `oem writesecureflag` | hboot | **dead** — gated on a physical HTC JavaCard (`checkKeycardID = -1`) |
| `fastboot flash` / RUU zip | hboot | **dead** — signature-gated at the door |
| ATS debug bypass | hboot strings | **dead** — needs a signed provisioning blob *and* an SD card (slot input) |

What this phase *did* produce is the thing that later mattered: **kernel code
execution on the stock ROM**.  A loadable module built from scratch — correct
vermagic, hand-built `struct module`, and `__versions` CRCs lifted from the
running kernel — became the tool that could later reach the PMIC.

Lesson recorded: a negative result is only worth something if it is *measured*.
Every row above is an experiment, not an opinion.

## 2. Phase 2 — reading hboot (where the actual answer was hiding)

The next line of attack was a bootloader weakness: the unlock-token verifier,
the flash-image verifier, the ~45 `oem` commands reachable while LOCKED.
hboot is a **binary** — a 4 MB dump of `/dev/block/mmcblk0p11`, no source, no
symbols, ARM/Thumb-2, load address `0x0F500000`:

```
offset 0x000c  0x0F500000     load address
offset 0x0010  0x1FFCD8       image size (~2 MB used of 4 MB)
offset 0x002c  "3.19.0.0000"  version
offset 0x0048  "SHIP"         build type
```

### The technique that made it readable

Naive string-address searches find nothing, because hboot references strings
**PC-relatively**:

```
ldr.w rX, [pc, #imm]     ; loads an *offset*
add   rX, pc             ; string = offset + (address of the ADD + 4)
```

`tools/xref2.py` decodes one instruction at **every 2-byte offset** (linear
sweeps drift permanently after the first misaligned Thumb decode), detects
that `ldr`-literal + `add pc` shape, resolves the target, and records it.  That
single heuristic yielded **2,730 resolved string references** — an index of
the binary keyed by string.

Reading a routine then becomes targeted work, not full decompilation:

1. find the string (`pg1fs_security`, `msm_mpu_emmc_protect: ...`,
   `writesecureflag`, `unlocktoken`);
2. look up the referencing code address;
3. disassemble that function, resolve literal pools, follow `bl`/`blx`
   recursively (`tools/hbwalk.py` is the recursive-descent walker);
4. decode dispatch tables where they appear (the OEM command table and the
   `f5030b8` state-query `TBH` jump table both had to be parsed to find the
   handlers behind `*** UNLOCKED ***` / `device unlocked!!`);
5. cross-reference against open-source code from the same lineage to *name*
   what you are looking at — Qualcomm's LK
   (`platform/msm_shared/mmc.c`) shares the write-protect code, and hboot's
   own strings (`wp_grpsize`, `EMMC_WP_MAGIC_2 type:%X`) confirm it.

### What that produced

The flag and its writer:

```
read_secure_flag() (f5318dc) -> first dword of the pg1fs "security" payload
f50e7a8:  S-ON iff that dword > 1
f531898(value):
    buf = *(0x0F6A3A7C)        ; pg1fs_security buffer loaded at boot
    *(u32 *)buf = value
    f504ee4("pg1fs_security", 0, buf, 0x1000)
```

and the routine that protects it:

```
partition_write_prot_mmc(start, end, mode):
    start_lba = partition_lookup(start)
    end_lba   = partition_lookup(end) + size(end)
    emmc_init()
    grp = driver_op8(cmd:8)                 ; => wp group size
    for (lba = start_lba; lba < end_lba; lba += grp)
        driver_op9(cmd:9, table:{lba, mode}, count:2)   ; CMD28 / CMD29
```

That second transcription is the hinge of the entire project.  The string
next to it says *`msm_mpu_emmc_protect`*, which sounds like a SoC/TZ-enforced
lock.  The body says otherwise: it is a loop of MMC **write-protect group**
commands aimed at the card.

### Known errors, kept in the record

Disassembly reading is error-prone and the repo records the mistakes: a
dispatch-table parse was off by four bytes for some entries, the trustlet
offsets were wrong once and corrected, and the *name* `msm_mpu_*` misled us
until the function was read end to end.

## 3. The reframe — from "defeat a verifier" to "enumerate a state"

Every Phase-1 route was an attempt to **defeat a verification step** (RSA,
signature, fuse, SoC policy).  All of them were hardened.

The S-OFF flag turned out to need none of that: it has no CRC and no
signature; only bytes 0 and 8 of the sector are non-zero.  Its only protection
is a **hardware state**: write-protect groups armed by hboot at boot.  That
moved the question from cryptography to physics:

1. **What** is armed?  → `CMD31 SEND_WRITE_PROT_TYPE` answered: group 0,
   `type 2 POWER-ON`.
2. **When?**  → every boot; measured by arming a group ourselves with
   `CMD6 EXT_CSD[171]=PWR_WP_EN` + `CMD28`, rebooting, and watching it come
   back unprotected while hboot's own ranges were re-armed.
3. **By whom?**  → hboot's `partition_write_prot_mmc()` (above).
4. **What clears it?**  → the JEDEC eMMC spec: `PWR_WP` is *volatile*; only a
   genuine VCC power cycle clears it.  Not `CMD29` (that is temporary WP),
   not a bus reset.

Question 2 is the one that opens the door: if the protection is re-created
every boot, then a writable window **provably exists** — the trick is to
manufacture it on demand.

## 4. Phase 3 — the write-protect investigation

### How "the write is silently dropped" was found

Not by reading code — by a differential write test that walked down the
storage stack:

1. `pwrite` into the `pg1fs` partition returned a full byte count, and the
   read-back was unchanged.
2. The same binary wrote successfully to `misc`, `pdata`, `cache`, `radio` —
   the control that rules out root/mount/SELinux.
3. Bypassing the filesystem with `pwrite` to `/dev/block/mmcblk0` at the raw
   LBA: still dropped.
4. Bypassing the block layer with raw `MMC_IOC_CMD` (CMD24): accepted,
   still dropped.
5. So the card was asked directly: `CMD13` status showed `WP_VIOLATION`
   (R1 bit 26) and `CMD31` showed group 0 as `POWER-ON`.  Per JEDEC, a
   write into a protected group is *accepted and discarded*, which is exactly
   the silent behaviour measured in step 1.  Public corroboration:
   **CVE-2014-9961** (eMMC power-on write-protect bypass).

The first pass of this investigation had three instrumentation bugs, all
recorded in `EMMC_WP_BYPASS.md` §3: the wrong EXT_CSD byte was poked (166
instead of 171), the R1 status word was never decoded (so "vanished" and
"refused" were not distinguished), and no WP *type* read was ever taken —
and the type is the single measurement the whole route depends on.

### Eliminating the clean ways to get a power cycle

| idea | measurement | verdict |
|---|---|---|
| `CMD29 CLEAR_WRITE_PROT` | type is POWER-ON, not temporary | no effect |
| `mmc_hw_reset` / RST_n | card re-enumerates perfectly, bitmap unchanged | no effect |
| suspend / resume | DT marks the rail `qcom,vdd-always-on`; the driver only switches to low-power mode | VCC never drops |
| lower the rail voltage | DT pins `min == max == 2950000 uV`, `set_voltage` -> `-EINVAL` | impossible |
| ATS debug flag | requires a signed provisioning blob + SD card transport | not available |
| `misc`/BCB boot command | tested with `Reboot`/`RebootATS` strings; WP arming unaffected | closed |

Which leaves one option: cut VCC for real, and bring it back.

### The insight (from HTC's own kernel, not from an exploit)

`regulator_force_disable("8941_l20")` *did* cut the card — hardware state
read `disabled` — but `regulator_enable()` afterwards returned `rc=0` while
the rail stayed off, six retries in a row.  The contradiction sent us to the
kernel's own regulator core:

```c
static int _regulator_force_disable(struct regulator_dev *rdev) {
        if (rdev->desc->ops->disable) ret = rdev->desc->ops->disable(rdev);
}                                   /* driver callback; use_count untouched */

static int _regulator_enable(struct regulator_dev *rdev) {
        if (rdev->use_count == 0) { ... ret = rdev->desc->ops->enable(rdev); }
        rdev->use_count++;
}
```

For an always-on resource the framework's enable path is only a vote; the
**driver op** is the actual switch.  So drive the hardware callbacks
directly, in both directions:

```
rdev = *(void **)((char *)reg + 0x30);
desc = *(void **)(rdev + 0x00);
ops  = *(void **)(desc + 0x10);
enable  = *(void **)(ops + 0x1c);
disable = *(void **)(ops + 0x20);
isen    = *(void **)(ops + 0x24);
```

That is `kmod/emmcpwr/emmcpwr12.c` — the whole trick.

### Making it survivable (engineering, not discovery)

Each earlier module version died on a real constraint, and each constraint
became a rule:

* disable the card's background GC first (`CMD6 EXT_CSD[163] = 0`) or
  `mmc_stop_bkops` blocks inside suspend;
* never `FIFREEZE` `/data` — a freeze that cannot complete wedges `su` and
  even `sync()`; remount read-only instead;
* keep the device awake — a suspended host fails card re-init with `-EILSEQ`;
* stage the tools in `/dev` (tmpfs) so they survive the block device
  disappearing;
* re-enumerate deliberately: `mmc_suspend_host` -> driver-op disable ->
  driver-op enable -> `mmc_power_off`/`mmc_power_up` -> `mmc_reinit`;
* verify before writing: `CMD31` bitmap must read `none` and a scratch write
  at LBA 4130 (unused sector in the *same* 16 MiB group as the flag) must land;
* write the flag in the **same boot session** — hboot re-arms on the next boot.

### The module ladder (each version kills one hypothesis)

| module | hypothesis | result |
|---|---|---|
| `emmcpwr2` | suspend/resume alone clears it | no — rail never drops |
| `emmcpwr4` | cut + `mmc_detach_bus` + `mmc_rescan` re-enumerates | no — `mmc_rescan` bails when `bus_ops != NULL` (non-removable card) |
| `emmcpwr9/10` | brown-out via voltage scaling | no — DT clamps the voltage |
| `emmcpwr11` | assert RST_n (`mmc_hw_reset`) | no — card resets, `PWR_WP` survives |
| `emmcpwr12` | driver ops for disable **and** enable | **yes** — `type 0 none`, scratch write lands, flag written |

## 5. Why this was not in any researcher's playbook

The published work in this space is about **crossing a privilege boundary**
(TrustZone, boot ROM, signature verification).  This route does not cross
one: it uses the fact that the phone's own power-management stack is
*permitted* to switch the eMMC rail, and that the protection depended on
volatile state rather than a fuse.

The Phase-1 work was still necessary — not for the answer, but for the
*tools*: without kernel code execution there is no way to call a PMIC driver
op, and without the eliminations there would have been no reason to believe
the rail was the last remaining lever.

## 6. Reusable rules from this project

1. **Prove the negatives.**  "Hardened" is only useful if measured; every
   dead end above is an experiment with an output.
2. **Distrust the name.**  `msm_mpu_emmc_protect` sounds like a SoC lock and
   is a CMD28 loop.  Read the body.
3. **When a write is accepted and does not happen, descend a layer.**  FS ->
   block device -> raw command -> device register.  Run a control region in
   the same experiment.
4. **Separate what is enforced from what is merely armed.**  Volatile state
   can be destroyed by whoever controls power; ask when the state is created
   and by whom.
5. **Read the vendor's own code for the mechanism, then verify on hardware.**
   The driver-op trick came out of HTC's regulator core; the confirmation came
   from `CMD31` and a scratch write, not from the reading.
6. **Keep the failures.**  The wrong verdict, the wrong EXT_CSD byte and the
   off-by-four table parse are in these documents on purpose — they are the
   difference between a story and a method.

## 7. Evidence index

| document | what it holds |
|---|---|
| `HBOOT_ANALYSIS.md` | hboot image layout, string-xref method, command table, CID gate |
| `SOFF_FLAG.md` | flag location/semantics, hboot reader/writer, `partition_write_prot_mmc` |
| `EMMC_WP_BYPASS.md` | the write-protect mechanism, CMD28/29/30/31, the tool bugs |
| `EMMC_WP_VOLATILE.md` | proof the protection is volatile; the correct chain |
| `FINAL_VERDICT_SOFF.md` | the (wrong) "impossible" verdict, with its correction |
| `STATE_OF_THE_HUNT.md` | consolidated evidence table for every route |
| `BOOTLOADER_UNLOCK_FLAG.md` | the lock flag: values, hboot writer `f52faa0`, reader, banner mapping |
| `tools/xref2.py`, `tools/hbwalk.py` | the disassembly/xref machinery |
| `tools/emmcwp.c` | CMD28/29/30/31 + R1 decode + scratch write test |
| `tools/kmod_emmcpwr/` | the module ladder, ending at `emmcpwr12.c` |
