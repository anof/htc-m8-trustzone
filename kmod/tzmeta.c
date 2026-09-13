/* ELF metadata for the module: modinfo, __versions, and __this_module.
 *
 * Layout of struct module was extracted from a stock device .ko
 * (evbug.ko): name @0x0c, init @0xbc, exit @0x160, total size 0x168.
 * __versions entries are {u32 crc; char name[60]} - stride 64, because
 * MODULE_NAME_LEN == 64 - sizeof(unsigned long) on 32-bit.
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

/* CRCs read from the running kernel's __kcrctab via /proc/kallsyms +
 * the decompressed vmlinux; each was validated against a stock .ko. */
/* NB: the variable is not named "__versions" - that would collide with the
 * section symbol LLVM synthesises for the section of the same name. */
static const struct modversion_info __mod_versions[]
	__attribute__((section("__versions"), used)) = {
	{ 0xf279f518u, "module_layout" },
	{ 0x27e1a049u, "printk" },
	{ 0x3102c636u, "scm_call_atomic2" },
	{ 0x40de35fdu, "scm_call_atomic3" },
	{ 0x88639bd5u, "scm_call_atomic1" },
	{ 0xdfabe0ffu, "scm_call" },
	{ 0x93fca811u, "__get_free_pages" },
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
	.name = "tzmod",
	.init = init_module,
	.exit = cleanup_module,
};
