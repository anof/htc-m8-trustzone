# HTC One (M8) Verizon — TrustZone port findings

Date: 2026-09-12
Device: HTC One (M8) Verizon, hboot 3.19.0.0000, S-ON, CID VZW__001, MID 0P6B20000
TZ image: `tz.img` sha256 69fbfaf6...502216 / TZ.BF.2.0-2.0.0114

## What was accomplished

1. **Working kernel code execution.** Built a loadable module from scratch with
   an LLVM ARM toolchain: correct vermagic, `__versions` with real CRCs pulled
   from the running kernel's `__kcrctab`, hand-built `struct module`
   (name@0x0c, init@0xbc, exit@0x160, size 0x168), e_flags 0x05000000.
   Loads and runs (`init_module -> 0`).

2. **Full TrustZone address map derived offline** for this device, by
   cross-matching against the Nexus 5 KTU84P image (same codebase, identical
   segment layout). See `htc_symbols.py`.

3. **All required SCM commands confirmed live:**
   `es_is_activated`, `es_save_partition_hash`, `get_diag`, `fver_get_version`,
   `security_allows_mem_dump`, `prng_getdata` — all report available.

4. **Register SCMs work, and cache handling is solved.** TrustZone writes to a
   caller buffer are invisible through a cached mapping; CP15 clean/invalidate
   around the call makes them visible. `fver_get_version(0)` returns 0x400000,
   independently confirming the derived `VERSION_CODE_0_DWORD_ADDRESS`.

## The blocker

**HTC's TZ validates SCM target addresses and refuses secure memory.**

Measured on-device:

| call | target | result |
|---|---|---|
| `es_is_activated(scratch, 0)` | non-secure DRAM | `0` — writes 0 to target |
| `es_is_activated(0xfe8256a4, 0)` | TZ | **`0xffffffee`** (refused) |
| `es_is_activated(0xA000, 0)` | low DRAM | `0` |
| `es_is_activated(0, 0)` | null | `0xfffffff0` |
| `prng_getdata(scratch, 8)` | non-secure DRAM | `0` — random bytes land |
| `prng_getdata(0xfe8256a4, 1)` | TZ | **`0xffffffee`** (refused) |
| `fver_get_version(0, TZ, 4)` | TZ | **`0xffffffee`** (refused) |
| `security_allows_mem_dump(_, TZ)` | TZ | **`0xffffffee`** (refused) |

Also: `es_is_activated` writes the **ES state (always 0)**, not its second
argument. So it is a "write a zero to a *non-secure* address" primitive.

### Why this ends the published route

`laginimaineb/MSM8974_exploit` bootstraps by using that wild zero-write to
zero TrustZone's own bounds-check dword, then uses the now-unchecked
`tzbsp_fver_get_version` / `tzbsp_get_diag` pointer slots to build arbitrary
read/write inside TZ.

On this build every one of those writes needs a **secure** target, and the
address validator refuses secure targets *before* bounds checks can be
disabled. Nexus 5's TZ.BF.2.0-2.0.0087 does not have this check; HTC's
TZ.BF.2.0-2.0.0114 does. The chicken-and-egg cannot be broken with these
primitives.

## Correction on `security_allows_mem_dump`

Disassembly shows its real signature is `(addr, len)`: it validates
`[addr, addr+len)` and then writes a bool to `*addr`. An earlier probe passed
mismatched arguments and produced a misleading "address map" — ignore that.
Called correctly:

```
sad(non-secure, 4)   -> 0          accepted
sad(0xA000, 4)       -> 0          accepted
sad(BOUNDS_DWORD, 4) -> ffffffee   rejected (TZ kernel)
sad(FVER_SCRATCH, 4) -> ffffffee   rejected (TZ kernel)
```

Notably `sad(0x07A00000, 4)` is accepted. `0x07A00000` is a **RWX segment in
the TZ image**, but the normal world reads that physical page as all zeros
while TZ's image has real code there — TrustZone has its own protected
physical memory. So this is not a window into TZ's code region; it is simply
ordinary RAM as far as the validator is concerned.

## Other commands probed

`set_cpu_ctx_buf`, `set_l1/l2/ocmem_dump_buf`, `memprot_sd_ctrl` — all return
`0xfffffff0` (invalid argument) for every argument count tried.

`set_boot_addr` and `sec_cfg_restore` return `0`, but disassembly shows
`set_boot_addr` stores its **second** argument into *fixed* TZ globals
(`0xfe82c06c`/`0xfe82c07c`) selected by bits of the first — not an
arbitrary-address write. `sec_cfg_restore` treats its argument as a mode
(0/1/3/5) and fell through harmlessly.

## Conclusion

The software-only S-OFF route via the published MSM8974 TrustZone exploit is
**not viable on this device** as published, because HTC hardened the SCM
address validation. Remaining unexplored avenues would require finding a
*different* TZ bug (memory corruption in a trustlet, or the `tzbsp_exec_smc`
family) — a much larger research project with no guarantee of success.
