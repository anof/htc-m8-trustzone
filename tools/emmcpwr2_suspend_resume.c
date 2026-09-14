/* emmcpwr2 - power-cycle the eMMC through the MMC core's own suspend/resume
 * path, so the card is quiesced and notified before VCC is cut and is fully
 * re-initialised afterwards.  Clearing the card's volatile POWER-ON
 * write-protect groups is what makes the S-OFF flag writable from Android.
 *
 * init_module() returns:
 *    0  success (card power-cycled and re-initialised)
 *  -20  mmc_suspend_host/mmc_resume_host not found
 *  -21  msm_sdcc.1 platform device not found
 *  -22  mmc0 host not found among its children
 *  -23  regulator_get(8941_l20) failed
 *  -24  mmc_suspend_host failed (nothing was touched)
 *  -25  mmc_resume_host failed
 */
typedef unsigned int u32;

#define NULL ((void *)0)

extern int printk(const char *fmt, ...);
extern unsigned long kallsyms_lookup_name(const char *name);
extern void msleep(unsigned int ms);
extern void *regulator_get(void *dev, const char *id);
extern int regulator_force_disable(void *reg);
extern int regulator_enable(void *reg);
extern void *platform_bus_type;
extern void *bus_find_device_by_name(void *bus, void *start, const char *name);
extern int device_for_each_child(void *parent, void *data,
				 int (*fn)(void *dev, void *data));

int init_module(void);
void cleanup_module(void);

static void *g_host;

static int find_mmc0(void *dev, void *data)
{
	/* struct device { struct device *parent; struct device_private *p;
	 *                  struct kobject kobj; ... }; kobj.name is at +0 of
	 * kobject, i.e. dev+8.  dev_name() is an inline (no symbol). */
	const char *n = *(const char **)((char *)dev + 8);
	(void)data;
	if (n && n[0] == 'm' && n[1] == 'm' && n[2] == 'c' &&
	    n[3] == '0' && n[4] == 0) {
		/* struct mmc_host { struct device *parent;
		 *                    struct device class_dev; ... } */
		g_host = (void *)((char *)dev - 4);
		return 1;
	}
	return 0;
}

int init_module(void)
{
	int (*p_susp)(void *);
	int (*p_res)(void *);
	void *pdev, *reg;
	int rc;

	p_susp = (int (*)(void *))kallsyms_lookup_name("mmc_suspend_host");
	p_res = (int (*)(void *))kallsyms_lookup_name("mmc_resume_host");
	printk("emmcpwr2: susp=%p res=%p\n", p_susp, p_res);
	if (!p_susp || !p_res)
		return -20;
	pdev = bus_find_device_by_name(&platform_bus_type, NULL, "msm_sdcc.1");
	if (!pdev)
		return -21;
	device_for_each_child(pdev, NULL, find_mmc0);
	if (!g_host) {
		printk("emmcpwr2: no mmc0 child\n");
		return -22;
	}
	printk("emmcpwr2: host=%p parent=%p\n", g_host, *(void **)g_host);
	reg = regulator_get(NULL, "8941_l20");
	if (!reg || (unsigned long)reg >= (unsigned long)-4095) {
		printk("emmcpwr2: regulator_get failed (%p)\n", reg);
		return -23;
	}
	rc = p_susp(g_host);
	printk("emmcpwr2: suspend -> %d\n", rc);
	if (rc)
		return -24;	/* do not cut power unless the card is quiesced */
	printk("emmcpwr2: cutting eMMC VCC\n");
	regulator_force_disable(reg);
	msleep(60);
	regulator_enable(reg);
	msleep(60);
	rc = p_res(g_host);
	printk("emmcpwr2: resume -> %d\n", rc);
	msleep(2000);
	if (rc)
		return -25;
	printk("emmcpwr2: done\n");
	return 0;
}

void cleanup_module(void)
{
}
