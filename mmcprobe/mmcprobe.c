/* mmcprobe - read-only eMMC inspection.
 *
 * Reads EXT_CSD (CMD8) and the CID via the standard MMC_IOC_CMD ioctl, to
 * determine how the protected region is guarded. Motivation: Sean Beaupre's
 * SAMDUNK paper states "HTC uses data in a write protected region of eMMC",
 * so the question is which *kind* of eMMC write protection is in play -
 * permanent, power-on, or boot-partition.
 *
 * Touch nothing. Read only.
 *
 * usage: mmcprobe [device]        (default /dev/block/mmcblk0)
 */
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;

#define NULL ((void *)0)

extern int   printf(const char *fmt, ...);
extern void *memset(void *s, int c, unsigned int n);
extern void *memcpy(void *d, const void *s, unsigned int n);
extern int   open(const char *path, int flags, ...);
extern int   ioctl(int fd, unsigned long req, ...);
extern int   close(int fd);
extern int   read(int fd, void *buf, unsigned int n);
extern int  *__errno(void);
extern void  exit(int code) __attribute__((noreturn));
#define errno (*__errno())
#define O_RDONLY 0

int main(int argc, char **argv);
void start_c(long *sp) __attribute__((used));
void start_c(long *sp)
{
	int argc = (int)sp[0];
	char **argv = (char **)(sp + 1);
	exit(main(argc, argv));
}
void _start(void) __attribute__((naked));
void _start(void)
{
	__asm__ volatile ("mov r0, sp\n\t" "b start_c\n\t");
}

struct mmc_ioc_cmd {
	int  write_flag;
	int  is_acmd;
	u32  opcode;
	u32  arg;
	u32  response[4];
	u32  flags;
	u32  blksz;
	u32  blocks;
	u32  postsleep_min_us;
	u32  postsleep_max_us;
	u32  data_timeout_ns;
	u32  cmd_timeout_ms;
	u32  __pad;
	u64  data_ptr;          /* offset 0x40, 8-byte aligned */
};

#define MMC_RSP_PRESENT (1u<<0)
#define MMC_RSP_CRC     (1u<<2)
#define MMC_RSP_OPCODE  (1u<<4)
#define MMC_CMD_ADTC    (1u<<5)
#define MMC_RSP_R1      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)

/* _IOWR(179, 0, sizeof(struct mmc_ioc_cmd)=72) */
#define MMC_IOC_CMD 0xC048B300u

static u8 ext_csd[512];

static void dump_hex(const u8 *p, int len, int base)
{
	int i;
	for (i = 0; i < len; i++) {
		if ((i & 15) == 0) printf("\n  %03x:", base + i);
		printf(" %02x", p[i]);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	const char *dev = "/dev/block/mmcblk0";
	struct mmc_ioc_cmd cmd;
	int fd, i;

	if (argc > 1) dev = argv[1];

	printf("mmcprobe: sizeof(struct mmc_ioc_cmd) = %u (expect 72)\n",
	       (unsigned)sizeof(struct mmc_ioc_cmd));

	fd = open(dev, O_RDONLY);
	if (fd < 0) { printf("[-] open %s failed: errno %d\n", dev, errno); return 1; }
	printf("[+] opened %s (fd=%d)\n", dev, fd);

	/* ---- CMD8 SEND_EXT_CSD, 512 bytes ---- */
	memset(&cmd, 0, sizeof(cmd));
	memset(ext_csd, 0, sizeof(ext_csd));
	cmd.write_flag = 0;
	cmd.is_acmd = 0;
	cmd.opcode = 8;
	cmd.arg = 0;
	cmd.flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmd.blksz = 512;
	cmd.blocks = 1;
	cmd.data_timeout_ns = 0x10000000;
	cmd.data_ptr = (u64)(unsigned long)ext_csd;

	if (ioctl(fd, MMC_IOC_CMD, &cmd) < 0) {
		printf("[-] CMD8 SEND_EXT_CSD failed: errno %d\n", errno);
		close(fd);
		return 1;
	}
	printf("[+] EXT_CSD read. response=%08x %08x %08x %08x\n",
	       cmd.response[0], cmd.response[1], cmd.response[2], cmd.response[3]);

	/* ---- decode the fields that matter ---- */
	printf("\n=== identity ===\n");
	printf("  EXT_CSD_REV [192]        = %u\n", ext_csd[192]);
	printf("  CARD_TYPE   [196]        = %02x %02x\n", ext_csd[196], ext_csd[197]);

	printf("\n=== write protection configuration ===\n");
	printf("  WR_REL_PARAM   [166]     = %02x\n", ext_csd[166]);
	printf("  BOOT_WP        [173]     = %02x   (B_PWR_WP_EN=%d B_PERM_WP_EN=%d B_PWR_WP_DIS=%d B_PERM_WP_DIS=%d)\n",
	       ext_csd[173],
	       !!(ext_csd[173] & 0x01), !!(ext_csd[173] & 0x04),
	       !!(ext_csd[173] & 0x40), !!(ext_csd[173] & 0x10));
	printf("  ERASE_GROUP_DEF[175]     = %02x\n", ext_csd[175]);
	printf("  PART_CONFIG    [179]     = %02x\n", ext_csd[179]);
	printf("  HC_WP_GRP_SIZE [221]     = %02x\n", ext_csd[221]);
	printf("  HC_ERASE_GRP_SIZE[224]   = %02x\n", ext_csd[224]);
	printf("  PARTITION_ATTR [156]     = %02x\n", ext_csd[156]);
	printf("  PART_SUPPORT   [160]     = %02x\n", ext_csd[160]);
	printf("  PART_SET_COMPL [155]     = %02x\n", ext_csd[155]);
	printf("  SEC_FEATURE_SUP[231]     = %02x\n", ext_csd[231]);
	printf("  RPMB_MULT      [168]     = %02x\n", ext_csd[168]);

	printf("\n=== fields the kernel also tracks ===\n");
	for (i = 0; i < 8; i++) {
		(void)i;
		break;
	}
	printf("  BUS_WIDTH [183]=%02x  HS_TIMING [185]=%02x  CACHE_CTRL [33]=%02x\n",
	       ext_csd[183], ext_csd[185], ext_csd[33]);

	printf("\n=== full EXT_CSD (bytes 0x0f0-0x1ff) ===\n");
	dump_hex(ext_csd + 0xf0, 0x110, 0xf0);

	printf("\n=== full EXT_CSD (bytes 0x000-0x0ef) ===\n");
	dump_hex(ext_csd, 0xf0, 0);

	/* ---- CMD31 SEND_WRITE_PROT / CMD30 SEND_WRITE_PROT_TYPE ----
	 * Ask the card directly whether a given address sits in a
	 * write-protected group, and if so which type. */
	printf("\n=== per-address write-protect query (CMD31 / CMD30) ===\n");
	{
		static const u32 addrs[] = {
			0x00000000u,   /* start of user area            */
			0x00004000u,
			0x00100000u,
			0x00400000u,
			0x00800000u,   /* ~4 GB                         */
			0x02000000u,
			0x04000000u,
			0x06000000u,
			0x08000000u,
			0x0A000000u,
			0x0C000000u,
			0x0E000000u,
		};
		unsigned int k;
		for (k = 0; k < sizeof(addrs)/sizeof(addrs[0]); k++) {
			struct mmc_ioc_cmd c31, c30;
			int r31, r30;

			u8 wp = 0xEE, wt = 0xEE;

			memset(&c31, 0, sizeof(c31));
			c31.write_flag = 0;
			c31.opcode = 31;                 /* SEND_WRITE_PROT */
			c31.arg = addrs[k];
			c31.flags = MMC_RSP_R1 | MMC_CMD_ADTC;
			c31.blksz = 1;
			c31.blocks = 1;
			c31.data_timeout_ns = 0x10000000;
			c31.data_ptr = (u64)(unsigned long)&wp;
			r31 = ioctl(fd, MMC_IOC_CMD, &c31);

			memset(&c30, 0, sizeof(c30));
			c30.write_flag = 0;
			c30.opcode = 30;                 /* SEND_WRITE_PROT_TYPE */
			c30.arg = addrs[k];
			c30.flags = MMC_RSP_R1 | MMC_CMD_ADTC;
			c30.blksz = 1;
			c30.blocks = 1;
			c30.data_timeout_ns = 0x10000000;
			c30.data_ptr = (u64)(unsigned long)&wt;
			r30 = ioctl(fd, MMC_IOC_CMD, &c30);

			printf("  addr %08x : CMD31 r=%2d WP=0x%02x | CMD30 r=%2d TYPE=0x%02x\n",
			       addrs[k], r31, wp, r30, wt);
		}
	}

	/* ---- optional: CMD29 CLR_WRITE_PROT / CMD28 SET_WRITE_PROT ---- */
	if (argc > 3) {
		u32 lba = 0;
		const char *p = argv[3];
		int op = (argv[2][0] == 'c') ? 29 : 28;   /* clrwp | setwp */
		while (*p) {
			u32 v;
			char c = *p++;
			if (c >= '0' && c <= '9') v = c - '0';
			else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
			else continue;
			lba = lba * 16 + v;
		}
		{
			struct mmc_ioc_cmd c;
			int r;
			memset(&c, 0, sizeof(c));
			c.write_flag = 1;          /* CMD28/29 are R1b, no data */
			c.opcode = op;
			c.arg = lba;
			c.flags = MMC_RSP_R1 | (1u << 3) | (1u << 6); /* PRESENT|CRC|OPCODE|BUSY + SPI_S1 */
			r = ioctl(fd, MMC_IOC_CMD, &c);
			printf("\n[CMD%d] lba=%u (0x%x) -> ret=%d errno=%d resp=%08x\n",
			       op, lba, lba, r, r ? errno : 0, r ? 0 : c.response[0]);
		}
	}

	close(fd);
	return 0;
}
