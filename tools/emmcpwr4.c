/* emmcpwr4 - clear the eMMC's volatile POWER-ON write protection (v2).
 *
 * Same idea as emmcpwr3 but without the MMC suspend path (which can block in
 * mmc_stop_bkops while the card runs background GC).  Instead:
 *
 *   1. find the mmc0 host (platform device -> children -> kobject name)
 *   2. force-cycle the eMMC's supply (pm8941_l20 is qcom,vdd-always-on, so
 *      the mmc driver never removes it) - the card's volatile write-protect
 *      groups are cleared by the power cycle
 *   3. mmc_detach_bus(host)  - drop the card the kernel still thinks is there
 *      (it is actually sitting in its idle state), leaving bus_ops == NULL
 *   4. mmc_detect_change(host, 0) - mmc_rescan now takes its re-enumeration
 *      path (it returns early only when bus_ops != NULL), so the card is
 *      re-initialised: CMD0/CMD1/CMD2/CMD3/CMD9/CMD7/CMD8
 *
 * Everything is resolved with kallsyms_lookup_name(), which on this kernel
 * (CONFIG_KALLSYMS_ALL) reaches non-exported globals such as mmc_detach_bus.
 *
 * init_module() return codes:
 *    0 ok                 -20 missing primitive   -21 no msm_sdcc.1
 *  -22 no mmc0 child      -23 no regulator        -24 detach failed
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
	const char *n = *(const char **)((char *)dev + 8);
	(void)data;
	if (n && n[0] == 'm' && n[1] == 'm' && n[2] == 'c' &&
	    n[3] == '0' && n[4] == 0) {
		g_host = (void *)((char *)dev - 4);
		return 1;
	}
	return 0;
}

int init_module(void)
{
	void (*p_detect)(void *, unsigned long);
	int (*p_detach)(void *);
	void *pdev, *reg;
	int rc;

	p_detect = (void (*)(void *, unsigned long))
		kallsyms_lookup_name("mmc_detect_change");
	p_detach = (int (*)(void *))kallsyms_lookup_name("mmc_detach_bus");
	printk("emmcpwr4: detect=%p detach=%p\n", p_detect, p_detach);
	if (!p_detect || !p_detach)
		return -20;
	pdev = bus_find_device_by_name(&platform_bus_type, NULL, "msm_sdcc.1");
	if (!pdev)
		return -21;
	device_for_each_child(pdev, NULL, find_mmc0);
	if (!g_host)
		return -22;
	reg = regulator_get(NULL, "8941_l20");
	if (!reg || (unsigned long)reg >= (unsigned long)-4095) {
		printk("emmcpwr4: no regulator (%p)\n", reg);
		return -23;
	}
	printk("emmcpwr4: host=%p - cutting eMMC VCC\n", g_host);
	regulator_force_disable(reg);
	msleep(30);
	regulator_enable(reg);
	msleep(80);
	rc = p_detach(g_host);
	printk("emmcpwr4: detach -> %d\n", rc);
	msleep(50);
	printk("emmcpwr4: scheduling rescan\n");
	p_detect(g_host, 0);
	msleep(2500);
	printk("emmcpwr4: done\n");
	return rc ? -24 : 0;
}

void cleanup_module(void)
{
}
