/* ELF metadata for dloadmod: modinfo, __versions, __this_module.
 * Mirrors kmod/tz/tzmeta.c (struct module layout from a stock evbug.ko).
 */
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
	{ 0xfb961d14u, "__arm_ioremap" },
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
	.name = "dloadmod",
	.init = init_module,
	.exit = cleanup_module,
};
