# Trustlet work — dynamic session (Check Point method), 2026-09-13

## Tool built

`tzprobe` (source in `edl_tools/tzprobe.c`, built like the keymaster PoC with
the device's `libQSEEComAPI.so`):

```
tzprobe enum  <firmware_dir> <app> <lo> <hi> [reqsz] [rspsz]
tzprobe send  <firmware_dir> <app> <cmd> <hexpayload> [rspsz]
tzprobe fuzz  <firmware_dir> <app> <cmd> <iters> [reqsz] [rspsz] [seed]
tzprobe smart <firmware_dir> <app> <cmd> [reqsz] [rspsz]
```

Key facts learned about the device's QSEECom stack:

* The userspace library builds the filenames itself: `"%s/%s.mdt"` and
  `"%s/%s.b%02d"` — so the *path argument is a directory*, e.g.
  `/system/etc/firmware` + app `dxhdcp2`. Passing a file path silently falls
  back to the kernel's firmware search path, which only covers the vendor
  directory (that is why only keymaster loaded at first).
* Replies land in the **same** ION buffer, at the first 0x40-aligned offset
  after the request; lengths passed to `QSEECom_send_cmd` must be 0x40-aligned
  (same convention as the working keymaster PoC).
* Trustlets loadable from a root shell: widevine, dxhdcp2, hcheck, mirlink,
  cmnlib. `mc_v2` is not a QSEE app (Trustonic MobiCore).
* Loading **cmnlib** as an app wedges the secure-world app manager:
  afterwards every `_check_app_exists` SCM call fails with `-55` and no app
  will start until the device is rebooted. (DoS only, but recorded.)

## Command surfaces (measured on-device)

| app | commands | notes |
|---|---|---|
| widevine | 0x61001–0x61026 (+0x20003 in the table) | matches the static table at merged offset 0x27f14; all answer with status word 0 |
| keymaster | 1 (generate keypair), 2 (import), 3 (sign), 4 (verify) | the CVE-2016-5349 PoC still works end-to-end |
| dxhdcp2 | **0, 1, 2, 3** | anything else returns status `0x0d0000xx`; command 2 answers `0x02000009` |
| hcheck | 0x11 | every other ID returns `0xfffffffa`; 0x11 replies `{1, 0xfffffede}` and ignores payload content (tested 16 B–4 KiB) |
| mirlink | 1..N | replies `{2, 0}` for every ID tested (0x0–0x100) |
| keymaster | 0..8 all accepted by the framework | real semantics only for 1–4 (from the CVE-2016-5349 PoC) |

### dxhdcp2 dispatcher and handlers (ARM/Thumb addresses)

```
code segment: merged offset 0x34b8, vaddr 0x0da10000, size 0x1c954
entry       0x0da10000
dispatch    0x0da11430   cmp.w r8,#1 / #2 / #3
  cmd 1 ->  0x0da1163c -> handler 0x0da1734c
  cmd 2 ->  0x0da11650 -> handler 0x0da17402
  cmd 3 ->  0x0da1164a -> handler 0x0da17494
  cmd 0 ->  0x0da11454 (session/config path)
```

The handlers use the standard QSEE IObject accessors
(`0x0da17b8a` = lookup field id < 0x40 from an 8-byte-entry table;
`0x0da17b02` = same with an insert path) — both are bounds-checked, so the
bug is expected deeper in the per-command copy logic.

## Fuzzing done (no crash found yet)

* widevine: 150 random payloads per command at each declared parameter size
  (~5,700 requests) — clean.
* widevine: structured sweep (`smart`) across all 38 commands — every 4-byte
  word of the parameter area set to 0/1/0xffff/0x10000/0x7fffffff/0x80000000/
  0xffffffff/0xdeadbeef/0x41414141/0x0da10000 — clean. (Requests whose size
  exceeds the declared parameter size are rejected by QSEECom itself with
  `-1`, so only in-spec content fuzzing is possible from the AP.)
* dxhdcp2: 200 random 4 KiB requests on each of commands 1, 2, 3 — clean.

The device survived everything (no secure-world reset), which means the bugs
Check Point found in dxhdcp2 need *structured* inputs that reach the copy
sites — their method (patch the TA to run as a user-space binary under
AFL/QEMU, as described in `trustlets/research/checkpoint_road_tz_fuzzing.md`)
is the natural next step.

## Exact next steps

1. Walk the three dxhdcp2 handlers (addresses above) looking for a copy or
   index with a request-derived length; the accessors are safe, so the bug —
   if it exists in this 2016 build — is in the code between them.
2. Port the trustlet to user space the Check Point way (patch import stubs to
   glibc, feed the command handler directly) and AFL it — the crash they found
   is patched in 2019, so it should still be present here.
3. Keep the *write*-primitive requirement in mind: the keymaster
   CVE-2016-5349 primitive is read-only and the XPU limits what it can read,
   so the goal remains a secure-world write (or an XPU/WP reconfiguration).

## Post-2016 CVEs that plausibly still affect this 2016 build

Mined from `trustlets/research/tz_tee_vulnerabilities.csv` + NVD descriptions:

| CVE | what it gives | why it matters here |
|---|---|---|
| CVE-2021-35122 | non-secure side can modify **XPU IO-space permission** ("RG permissions") due to missing input validation | a direct path to lifting the XPU restrictions that stop AP writes |
| CVE-2020-11252 | TZ init **disables xPUs when memory dumps are enabled** | if the dump-enable flag is reachable, the XPU windows open |
| CVE-2020-11199 | HLOS can map the **IMEM region** (improper access control) | IMEM already accessible to us via a module; would matter for a stock device |
| CVE-2020-11298 | TOCTOU on shared-memory permissions while a listener callback is pending | memory-corruption primitive in QSEE reachable from HLOS |
| CVE-2019-14119 | TOCTOU in QTEE | same family, earlier |
| CVE-2019-10561 | uninitialised locals passed to **SFS API** → invalid pointer dereference | DoS on paper, but an uninitialised *pointer* argument is a potential write primitive given heap grooming |
| CVE-2019-20590 | integer underflow in the Secure Storage trustlet (Samsung/Qualcomm, SVE-2019-13952) | Check Point fuzzing family; we do not ship `sec_store` |

`ucsb-seclab/boomerang` (the reference work for our working keymaster bug) ships
exactly **one** exploit — `keymaster_kernel_leak` (read-only). There is no
public write primitive for keymaster, so the read bug cannot be extended by
copying published code.

## Fuzzing status after this session

* dxhdcp2 commands 0,1,2,3 × sizes 32/256/2048 with the `smart` generator
  (every word set to 10 extreme values, rest zero): **no interesting replies,
  no crash**.
* widevine: 38 commands × random and structured payloads at declared sizes:
  **no crash**.
* hcheck 0x11 × 16 B–4 KiB structured: reply is constant, **no crash**.
* Total: on the order of 1e5 malformed requests, device never reset.

Conclusion: within what QSEECom allows the normal world to send (declared
param sizes), these builds look robust. The Check Point-class bugs need the
TA executed *off-device* (their patched-normal-world + AFL/QEMU setup, steps
documented in `trustlets/research/checkpoint_road_tz_fuzzing.md`), or a
different attack surface (QSEOS loader, listener/TOCTOU path, SFS API).
