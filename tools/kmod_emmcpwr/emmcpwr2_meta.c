/* ELF metadata for emmcpwr: modinfo, __versions, __this_module.
 * Layout of struct module taken from a stock device .ko (see kmod/tz). */
typedef unsigned int u32;

int init_module(void);
void cleanup_module(void);

static const char __modinfo[]
	__attribute__((section(".modinfo"), used)) =
	"license=GPL\0"
	"depends=\0"
	"intree=Y\0"
	"vermagic=3.4.0-ga264541 SMP preempt mod_unload modversions ARMv7 \0";

struct modversion_info {
	u32 crc;
	char name[60];
};

static const struct modversion_info __mod_versions[]
	__attribute__((section("__versions"), used)) = {
	{ 0xf279f518u, "module_layout" },
	{ 0x27e1a049u, "printk" },
	{ 0xe007de41u, "kallsyms_lookup_name" },
	{ 0xf9a482f9u, "msleep" },
	{ 0x09147f65u, "regulator_get" },
	{ 0x6114d8a4u, "regulator_force_disable" },
	{ 0x8a5c7a80u, "regulator_enable" },
	{ 0xa37e8374u, "mmc_detect_change" },
	{ 0x790fc712u, "class_find_device" },
	{ 0xcd4347fbu, "platform_bus_type" },
	{ 0xe74db350u, "bus_find_device_by_name" },
	{ 0x8c51cbf5u, "device_for_each_child" },
};

struct module_stub {
	char pad0[0x0c];
	char name[60];
	char pad1[0xbc - 0x0c - 60];
	int (*init)(void);
	char pad2[0x160 - 0xbc - 4];
	void (*exit)(void);
	char pad3[0x168 - 0x160 - 4];
};

struct module_stub __this_module
	__attribute__((section(".gnu.linkonce.this_module"), used)) = {
	.name = "emmcpwrH",
	.init = init_module,
	.exit = cleanup_module,
};
