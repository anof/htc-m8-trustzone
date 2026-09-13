# SCM handler audit — searching for an unchecked length field

Motivation: the Qualcomm TZ CVE record is dominated by one bug class —
**CWE-120, buffer copy without checking the size of input**, several of them
explicitly reachable "from HLOS" (the normal world). Examples: CVE-2023-21662,
CVE-2023-21664, CVE-2019-10589, CVE-2019-2288, CVE-2019-2321. The goal here
was to find the same class of bug in this 2016 build, since a later fix would
not be present.

## Method

Recover the 67-entry SCM descriptor table from `tz.img`, take each handler
address, disassemble it, build the call graph, and flag any handler that calls
a copy primitive without first calling a range validator.

## The primitives, identified by disassembly

| Address | What it is |
|---|---|
| `0xfe8199f4` | `memcpy` — `(r0=dst, r1=src, r2=len)`; ARM mode |
| `0xfe819970` | second `memcpy` variant (PLD-prefetching path) |
| `0xfe819df4` | `memmove` |
| `0xfe819918` | `memset` (zero fill) |
| `0xfe81a00c` | data-cache clean+invalidate by MVA over `[r0, r0+r1)` |

### The validation chain

`0xfe810784` and `0xfe81307c` are byte-identical duplicates of the same helper:

```
validate(addr, len):
    if (!sub_0xfe848b92(addr, len))        return 0    ; first-stage check
    table = *(u32*)0xFE825770
    return table_walk(table, addr, addr+len-1)
```

and `0xfe812720` is the table walk. Disassembling it confirms the structure of
the region table found earlier — it indexes `table + i*16` and compares the
requested `[start,end)` against each entry's `{index, count, start, end}`
fields. This is the mechanism behind `BOUNDS_CHECK_DWORD_ADDRESS`.

Further validators seen in use: `0xfe812ad4` (single value), `0xfe812afe`
(value + length), `0xfe816506` (search a `u16` list), plus inline range checks.

## Result

Of 67 SCM commands, **35 handlers live inside the dumped image**. All 35 were
disassembled. Every one of them validates its buffers before any copy, either
through the helper chain above or with an inline bounds check.

Two candidates initially looked unvalidated and both turned out to be checked
once examined in full:

* `tzbsp_is_service_available` (svc 6 cmd 1) — calls `0xfe812ad4(buf,1)` and
  `0xfe812afe(val,0xc)` before writing a byte to the caller's pointer.
* `tzbsp_vmidmt_set_memtype` (svc 0xc cmd 9) — inline `cmp r2,#8 / bhi fail`,
  so the third argument is bounded, and `arg1` must equal 4.

**No unchecked length field was found in any analyzable handler.**

## The limit of this approach

The other **32 handlers are not in the image**. They sit at `0xfe84xxxx` /
`0xfe85xxxx`, above the last ELF segment (`0xfe83c000` + its `0x4000` BSS), and
they are loaded at runtime into memory the normal world cannot read.

That group includes exactly the interesting ones:

```
tzbsp_es_is_activated            0xfe850897   <- the published exploit's primitive
tzbsp_es_save_partition_hash     0xfe850929
tzbsp_fver_get_version           0xfe84736d
tzbsp_pil_*                      (6)
tzbsp_qfprom_rollback_write_row  0xfe84fadf
tzbsp_memprot_*                  (5)
tzbsp_ssd_*                      (5)
tzbsp_ocmem_*                    (4)
tzbsp_smmu_*                     (2)
```

They are not in the `tz` partition beyond the ELF, not in `sbl1`, `sp1`,
`sdi`, `rpm`, `wifi` or `ddr` (all dumped and scanned for ELF images and for
`tzbsp_` strings — nothing). They would have to be dumped from live secure
memory, which is the thing we cannot do.

So the audit is complete for the half of the interface we can see, and the
half we cannot see is precisely where the one known-buggy primitive lives.

## Incidental finding

Program header 1 of the TZ ELF (`p_type = PT_NULL`, so a normal loader ignores
it) carries 7016 bytes for `0xfe840000`. It is not code: it is a header
(containing `0xfe840028`, `0xfe840268`, `0xfe840368` and sizes) followed by
32-byte hashes with zero padding — a secure-boot segment/hash table.
