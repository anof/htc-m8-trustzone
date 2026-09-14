/* emmcpwr12 - power-cycle the eMMC by driving pm8941_l20's *driver* ops
 * directly, the same way regulator_force_disable() does.
 *
 * Why the earlier attempts failed, from HTC's own drivers/regulator/core.c:
 *
 *   static int _regulator_force_disable(struct regulator_dev *rdev) {
 *        if (rdev->desc->ops->disable) ret = rdev->desc->ops->disable(rdev);
 *   }                                  <- direct op, use_count untouched
 *
 *   static int _regulator_enable(struct regulator_dev *rdev) {
 *        if (rdev->use_count == 0) {
 *                if (!_regulator_can_change_status(rdev)) return -EPERM;
 *                ... ret = rdev->desc->ops->enable(rdev);
 *        }
 *        rdev->use_count++;
 *   }
 *
 * The rail is regulator-always-on, so use_count is never 0 and every
 * regulator_enable() just bumps the count and returns 0 without touching the
 * hardware - measured live as "enable -> rc=0, enabled=0" six times while the
 * hardware state stayed disabled.  That is why the cut looked one-way.
 *
 * Offsets taken from this kernel's own code (regulator_enable @0xc04087b8 does
 * rdev = reg->rdev at +0x30, then rdev->desc at +0, desc->ops at +0x10 and
 * ops->enable at +0x1c; include/linux/regulator/driver.h confirms
 * enable/disable/is_enabled at 0x1c/0x20/0x24):
 *
 *     rdev    = *(void **)((char *)reg + 0x30)
 *     desc    = *(void **)((char *)rdev + 0x00)
 *     ops     = *(void **)((char *)desc + 0x10)
 *     enable  = *(void **)((char *)ops + 0x1c)   - rpm_vreg_enable
 *     disable = *(void **)((char *)ops + 0x20)   - rpm_vreg_disable
 *     isen    = *(void **)((char *)ops + 0x24)   - rpm_vreg_is_enabled
 *
 * init_module() returns
 *    0  card power-cycled (VCC really went down and came back) and re-inited
 *  -20/21/22/23/26/27  setup failures (nothing touched)
 *  -28  the ops table does not look sane - abort before cutting anything
 *  -24  suspend failed                 -41  VCC did not come back
 *  -25  card could not be re-initialised
 */
typedef unsigned int u32;

#define NULL ((void *)0)

extern int printk(const char *fmt, ...);
extern unsigned long kallsyms_lookup_name(const char *name);
extern void msleep(unsigned int ms);
extern void *regulator_get(void *dev, const char *id);
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
	int (*p_susp)(void *);
	int (*p_reinit)(void *);
	void (*p_power_off)(void *);
	void (*p_power_up)(void *);
	void *pdev, *reg, *rdev, *desc, *ops;
	int (*op_enable)(void *);
	int (*op_disable)(void *);
	int (*op_isen)(void *);
	int rc, i, cut = 0, suspend_ok = 0;

	p_susp = (int (*)(void *))kallsyms_lookup_name("mmc_suspend_host");
	p_reinit = (int (*)(void *))kallsyms_lookup_name("mmc_reinit");
	p_power_off = (void (*)(void *))kallsyms_lookup_name("mmc_power_off");
	p_power_up = (void (*)(void *))kallsyms_lookup_name("mmc_power_up");
	if (!p_susp || !p_reinit || !p_power_off || !p_power_up)
		return -20;
	pdev = bus_find_device_by_name(&platform_bus_type, NULL, "msm_sdcc.1");
	if (!pdev)
		return -21;
	device_for_each_child(pdev, NULL, find_mmc0);
	if (!g_host) {
		printk("emmcpwr12: no mmc0 child\n");
		return -22;
	}
	if (*(void **)g_host != pdev) {
		printk("emmcpwr12: parent mismatch - aborting\n");
		return -26;
	}
	reg = regulator_get(NULL, "8941_l20");
	if (!reg || (unsigned long)reg >= (unsigned long)-4095) {
		printk("emmcpwr12: regulator_get failed (%p)\n", reg);
		return -23;
	}
	rdev = *(void **)((char *)reg + 0x30);
	desc = *(void **)((char *)rdev + 0x00);
	ops = *(void **)((char *)desc + 0x10);
	op_enable = *(int (**)(void *))((char *)ops + 0x1c);
	op_disable = *(int (**)(void *))((char *)ops + 0x20);
	op_isen = *(int (**)(void *))((char *)ops + 0x24);
	printk("emmcpwr12: host=%p reg=%p rdev=%p desc=%p ops=%p\n", g_host, reg,
	       rdev, desc, ops);
	printk("emmcpwr12: enable=%p disable=%p is_enabled=%p now=%d\n",
	       op_enable, op_disable, op_isen, op_isen ? op_isen(rdev) : -1);
	if (!op_enable || !op_disable || !op_isen)
		return -28;

	rc = p_susp(g_host);
	printk("emmcpwr12: suspend -> %d\n", rc);
	if (rc)
		return -24;
	suspend_ok = 1;

	rc = op_disable(rdev);
	i = op_isen(rdev);
	printk("emmcpwr12: drv_disable -> rc=%d, is_enabled=%d\n", rc, i);
	if (i == 0) {
		cut = 1;	/* VCC really down: card POR, PWR_WP gone */
		msleep(200);
	}
	rc = op_enable(rdev);
	i = op_isen(rdev);
	printk("emmcpwr12: drv_enable -> rc=%d, is_enabled=%d\n", rc, i);
	{
		int n;
		for (n = 0; n < 5 && op_isen(rdev) == 0; n++) {
			msleep(100);
			rc = op_enable(rdev);
			printk("emmcpwr12: drv_enable retry %d -> rc=%d, "
			       "is_enabled=%d\n", n + 1, rc, op_isen(rdev));
		}
	}
	if (op_isen(rdev) == 0 && cut) {
		printk("emmcpwr12: RAIL DID NOT COME BACK\n");
		return -41;
	}
	msleep(200);

	/* Re-enumerate the card (device is kept awake, so this works). */
	p_power_off(g_host);
	msleep(100);
	p_power_up(g_host);
	rc = p_reinit(g_host);
	printk("emmcpwr12: mmc_reinit -> %d\n", rc);
	if (rc) {
		msleep(300);
		p_power_off(g_host);
		msleep(100);
		p_power_up(g_host);
		rc = p_reinit(g_host);
		printk("emmcpwr12: mmc_reinit retry -> %d\n", rc);
	}
	if (rc)
		return -25;
	printk("emmcpwr12: DONE cut=%d, rail=%d, card back\n", cut,
	       op_isen(rdev));
	if (!cut || !suspend_ok)
		return -41;
	return 0;
}

void cleanup_module(void)
{
}
