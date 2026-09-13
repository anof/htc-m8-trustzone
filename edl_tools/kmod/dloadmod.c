/* dloadmod - write the Qualcomm "dload mode" magic into IMEM.
 *
 * hboot's own to_sbldload path does f53b464(0x77665501) which pokes
 * 0xFE80565C and then resets; this module does the same poke from Android
 * so the reset can be triggered from the kernel side.
 */
typedef unsigned int u32;

int init_module(void);
void cleanup_module(void);

extern int printk(const char *fmt, ...);
extern void *__arm_ioremap(unsigned long phys, unsigned long size,
			   unsigned int mtype);

#define IMEM_PHYS 0xFE805000UL

/* IMEM offsets (base 0xFE805000, from the HTC 3.4 kernel source:
 * arch/arm/mach-msm/restart.c - RESTART_REASON_ADDR 0x65C,
 * DLOAD_MODE_ADDR 0x0, EMERGENCY_DLOAD_MODE_ADDR 0xFE0). */
#define OFF_DLOAD 0x0UL
#define OFF_RESTART_REASON 0x65CUL
#define OFF_EMERG 0xFE0UL

#define DLOAD_MAGIC 0x77665501u
#define EMERG_MAGIC1 0x322A4F99u
#define EMERG_MAGIC2 0xC67E4350u
#define EMERG_MAGIC3 0x77777777u

static volatile u32 *imem;

static void poke(unsigned long off, u32 val)
{
	volatile u32 *p = (volatile u32 *)((unsigned long)imem + off);
	u32 old = *p;

	*p = val;
	printk("<3>DLMOD: [%08lx] 0x%08x -> 0x%08x (rb 0x%08x)\n",
	       IMEM_PHYS + off, old, val, *p);
}

int init_module(void)
{
	imem = (volatile u32 *)__arm_ioremap(IMEM_PHYS, 0x1000, 0);
	if (!imem) {
		printk("<3>DLMOD: ioremap failed\n");
		return -1;
	}

	/* Qualcomm emergency download request (what "reboot edl" writes
	 * when CONFIG_MSM_DLOAD_MODE is enabled). */
	poke(OFF_EMERG, EMERG_MAGIC1);
	poke(OFF_EMERG + 4, EMERG_MAGIC2);
	poke(OFF_EMERG + 8, EMERG_MAGIC3);

	/* HTC hboot's own "reboot to download" marker. */
	poke(OFF_RESTART_REASON, DLOAD_MAGIC);

	/* Slots used by the EDL code-execution test payload. */
	printk("<3>DLMOD: test slot 0x100 = 0x%08x\n",
	       *(volatile u32 *)((unsigned long)imem + 0x100));
	printk("<3>DLMOD: test slot 0x104 = 0x%08x\n",
	       *(volatile u32 *)((unsigned long)imem + 0x104));
	printk("<3>DLMOD: test slot 0x110 = 0x%08x\n",
	       *(volatile u32 *)((unsigned long)imem + 0x110));

	{
		int i, hits = 0;
		for (i = 0; i < 64; i++) {
			u32 v = *(volatile u32 *)((unsigned long)imem + 0xC00 + i * 4);
			if ((v & 0xFFFF0000u) == 0x5A5A0000u)
				hits++;
		}
		printk("<3>DLMOD: EDL payload signature hits 0x%x/64, first words %08x %08x %08x %08x\n",
		       hits,
		       *(volatile u32 *)((unsigned long)imem + 0xC00),
		       *(volatile u32 *)((unsigned long)imem + 0xC04),
		       *(volatile u32 *)((unsigned long)imem + 0xC08),
		       *(volatile u32 *)((unsigned long)imem + 0xC0C));
	}

	__asm__ volatile("dsb sy" ::: "memory");
	return 0;
}

void cleanup_module(void)
{
}
