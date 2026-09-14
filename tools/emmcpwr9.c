/* emmcpwr9 - power-cycle the eMMC by *lowering its rail voltage*, not by
 * switching the rail off.
 *
 * Why: regulator_force_disable(pm8941_l20) does cut the card (hardware state
 * reads "disabled"), but regulator_enable() afterwards does NOT bring it back
 * - the RPM regulator's enable path is a one-way vote for this always-on
 * resource, so the eMMC stays dead until the whole device is reset and the
 * card never gets re-enumerated, which is what froze the phone.
 *
 * A voltage request is an ordinary resource vote: set the rail far below the
 * card's power-on-reset threshold and the card's volatile PWR_WP bitmap (armed
 * by hboot for groups 0..23 on every boot) is cleared exactly as by a power
 * cycle; put the voltage back and the rail is immediately usable again.
 *
 * The cut is verified before and after:
 *   - the achieved voltage is read back; if the request was clamped (the
 *     voltage never dropped) the card was never affected and we report it
 *   - after restoring, the voltage is read back again
 *   - the card is then re-enumerated with power_off -> power_up ->
 *     mmc_reinit (the block layer's own recovery sequence)
 *
 * init_module() returns:
 *    0  card was power-cycled (voltage actually dropped and came back) and
 *       re-initialised
 *  -20  a needed symbol is missing
 *  -21  msm_sdcc.1 not found          -22  no mmc0 child
 *  -26  host->parent mismatch         -23  regulator_get failed
 *  -24  mmc_suspend_host failed (nothing touched)
 *  -40  voltage request was clamped - card never lost power (nothing done)
 *  -41  the rail did not come back to its original voltage
 *  -25  card could not be re-initialised after the cycle
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

#define CUT_UV 1200000u		/* far below the card's POR threshold */
#define POR_UV 2000000u		/* "the card really lost power" ceiling */
#define MIN_OK_UV 2700000u	/* eMMC VCC(min) */

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
	int (*p_isen)(void *);
	int (*p_get_uv)(void *);
	int (*p_set_uv)(void *, int, int);
	void *pdev, *reg;
	int rc, v0, v1, v2, cut = 0, suspend_ok = 0;

	p_susp = (int (*)(void *))kallsyms_lookup_name("mmc_suspend_host");
	p_reinit = (int (*)(void *))kallsyms_lookup_name("mmc_reinit");
	p_power_off = (void (*)(void *))kallsyms_lookup_name("mmc_power_off");
	p_power_up = (void (*)(void *))kallsyms_lookup_name("mmc_power_up");
	p_isen = (int (*)(void *))kallsyms_lookup_name("regulator_is_enabled");
	p_get_uv = (int (*)(void *))kallsyms_lookup_name("regulator_get_voltage");
	p_set_uv = (int (*)(void *, int, int))
		kallsyms_lookup_name("regulator_set_voltage");
	printk("emmcpwr9: susp=%p reinit=%p poff=%p pon=%p isen=%p guv=%p "
	       "suv=%p\n", p_susp, p_reinit, p_power_off, p_power_up, p_isen,
	       p_get_uv, p_set_uv);
	if (!p_susp || !p_reinit || !p_power_off || !p_power_up || !p_isen ||
	    !p_get_uv || !p_set_uv)
		return -20;
	pdev = bus_find_device_by_name(&platform_bus_type, NULL, "msm_sdcc.1");
	if (!pdev)
		return -21;
	device_for_each_child(pdev, NULL, find_mmc0);
	if (!g_host) {
		printk("emmcpwr9: no mmc0 child\n");
		return -22;
	}
	printk("emmcpwr9: class_dev=%p host=%p parent=%p index=%d\n", g_dev,
	       g_host, *(void **)g_host, *(int *)((char *)g_host + 0x198));
	if (*(void **)g_host != pdev) {
		printk("emmcpwr9: parent mismatch - aborting\n");
		return -26;
	}
	reg = regulator_get(NULL, "8941_l20");
	if (!reg || (unsigned long)reg >= (unsigned long)-4095) {
		printk("emmcpwr9: regulator_get failed (%p)\n", reg);
		return -23;
	}
	v0 = p_get_uv(reg);
	printk("emmcpwr9: regulator=%p enabled=%d voltage=%d uV\n", reg,
	       p_isen(reg), v0);

	rc = p_susp(g_host);
	printk("emmcpwr9: suspend -> %d\n", rc);
	suspend_ok = (rc == 0);

	if (suspend_ok) {
		rc = p_set_uv(reg, CUT_UV, CUT_UV);
		v1 = p_get_uv(reg);
		printk("emmcpwr9: set %u uV -> rc=%d, now %d uV\n", CUT_UV, rc,
		       v1);
		if (v1 >= 0 && v1 <= (int)POR_UV) {
			cut = 1;
			msleep(400);	/* card is below POR: WP bitmap cleared */
		}
		rc = p_set_uv(reg, v0, v0);
		v2 = p_get_uv(reg);
		printk("emmcpwr9: restore %d uV -> rc=%d, now %d uV\n", v0, rc,
		       v2);
		if (cut && (v2 < (int)MIN_OK_UV || v2 < 0)) {
			printk("emmcpwr9: RAIL DID NOT COME BACK (%d uV)\n", v2);
			return -41;
		}
		msleep(300);
	}

	/* Bring the card back on a rail that is known to be up. */
	p_power_off(g_host);
	msleep(100);
	p_power_up(g_host);
	rc = p_reinit(g_host);
	printk("emmcpwr9: mmc_reinit -> %d\n", rc);
	if (rc && suspend_ok) {
		msleep(300);
		p_power_off(g_host);
		msleep(100);
		p_power_up(g_host);
		rc = p_reinit(g_host);
		printk("emmcpwr9: mmc_reinit retry -> %d\n", rc);
	}
	if (rc)
		return -25;

	printk("emmcpwr9: DONE cut=%d (v %d -> %d -> %d uV), card back\n",
	       cut, v0, v1, v2);
	if (!cut)
		return -40;
	return 0;
}

void cleanup_module(void)
{
}
