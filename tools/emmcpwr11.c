/* emmcpwr11 - clear the eMMC's volatile POWER-ON write protection by asserting
 * the card's *hardware reset* (RST_n) instead of cutting its supply.
 *
 * Why this and not the rail: regulator_force_disable(pm8941_l20) really does
 * cut the card (hardware state reads "disabled"), but on this firmware the
 * matching enable never takes effect - the rail stayed off through 1+5
 * regulator_enable() attempts with the device awake, so the card could never
 * be re-enumerated in that boot.  A voltage cut is equally impossible: the DT
 * pins that rail to min == max == 2950000 uV (set_voltage -> -22).
 *
 * This kernel has the eMMC Reset path backported:
 *   mmc_hw_reset(host) -> mmc_do_hw_reset(host, 0)
 *        -> mmc_host_clk_hold, mmc_set_clock(host->f_min)
 *        -> mmc_power_cycle(host)            /* host->ops->hw_reset
 *                                               (sdhci_hw_reset) drives RST_n
 *        -> host->bus_ops->reset(host)       /* card re-enumerated in place
 * A hardware reset puts the eMMC back into its power-on state, so the PWR_WP
 * bitmap hboot armed for groups 0..23 should be gone - and nothing needs to be
 * restored afterwards, because the rail was never touched and the block device
 * stays valid.
 *
 * init_module() returns:
 *    0  hardware reset issued and the card re-initialised
 *  -20  a needed symbol is missing
 *  -21  msm_sdcc.1 not found        -22  no mmc0 child
 *  -26  host->parent mismatch       -27  mmc_hw_reset failed and the
 *                                        power_cycle+reinit fallback failed
 */
typedef unsigned int u32;

#define NULL ((void *)0)

extern int printk(const char *fmt, ...);
extern unsigned long kallsyms_lookup_name(const char *name);
extern void msleep(unsigned int ms);
extern void *platform_bus_type;
extern void *bus_find_device_by_name(void *bus, void *start, const char *name);
extern int device_for_each_child(void *parent, void *data,
				 int (*fn)(void *dev, void *data));

int init_module(void);
void cleanup_module(void);

static void *g_host;
static void *g_dev;

static int find_mmc0(void *dev, void *data)
{
	const char *n = *(const char **)((char *)dev + 8);
	(void)data;
	if (n && n[0] == 'm' && n[1] == 'm' && n[2] == 'c' &&
	    n[3] == '0' && n[4] == 0) {
		g_dev = dev;
		g_host = (void *)((char *)dev - 8);
		return 1;
	}
	return 0;
}

int init_module(void)
{
	int (*p_hwreset)(void *);
	void (*p_pcycle)(void *);
	int (*p_reinit)(void *);
	void (*p_claim)(void *, void *);
	void (*p_release)(void *);
	void *pdev;
	int rc = -1, rc2 = -1;

	p_hwreset = (int (*)(void *))kallsyms_lookup_name("mmc_hw_reset");
	p_pcycle = (void (*)(void *))kallsyms_lookup_name("mmc_power_cycle");
	p_reinit = (int (*)(void *))kallsyms_lookup_name("mmc_reinit");
	p_claim = (void *)kallsyms_lookup_name("__mmc_claim_host");
	p_release = (void *)kallsyms_lookup_name("mmc_release_host");
	printk("emmcpwr11: hwreset=%p pcycle=%p reinit=%p claim=%p rel=%p\n",
	       p_hwreset, p_pcycle, p_reinit, p_claim, p_release);
	if (!p_hwreset || !p_pcycle || !p_reinit || !p_claim || !p_release)
		return -20;
	pdev = bus_find_device_by_name(&platform_bus_type, NULL, "msm_sdcc.1");
	if (!pdev)
		return -21;
	device_for_each_child(pdev, NULL, find_mmc0);
	if (!g_host) {
		printk("emmcpwr11: no mmc0 child\n");
		return -22;
	}
	printk("emmcpwr11: class_dev=%p host=%p parent=%p index=%d card=%p\n",
	       g_dev, g_host, *(void **)g_host,
	       *(int *)((char *)g_host + 0x198),
	       *(void **)((char *)g_host + 0x29c));
	if (*(void **)g_host != pdev) {
		printk("emmcpwr11: parent mismatch - aborting\n");
		return -26;
	}

	p_claim(g_host, NULL);
	rc = p_hwreset(g_host);
	printk("emmcpwr11: mmc_hw_reset -> %d\n", rc);
	if (rc) {
		/* mmc_hw_reset refuses when bus_ops->reset is missing or the
		 * card does not advertise RST_n; drive the reset directly and
		 * re-enumerate by hand. */
		p_pcycle(g_host);
		msleep(100);
		rc2 = p_reinit(g_host);
		printk("emmcpwr11: power_cycle+reinit -> %d\n", rc2);
	}
	p_release(g_host);
	msleep(200);
	printk("emmcpwr11: DONE hw_reset=%d fallback=%d\n", rc, rc2);
	if (rc && rc2)
		return -27;
	return 0;
}

void cleanup_module(void)
{
}
