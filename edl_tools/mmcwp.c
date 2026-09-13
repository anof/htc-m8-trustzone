/* mmcwp - eMMC write-protect inspection/clearing via MMC_IOC_CMD.
 *
 * usage:
 *   mmcwp csd    <dev>
 *   mmcwp extcsd <dev> <file>       dump 512-byte EXT_CSD
 *   mmcwp get    <dev> <lba>        CMD30 SEND_WRITE_PROT (32 group bits)
 *   mmcwp set    <dev> <lba>        CMD28 SET_WRITE_PROT
 *   mmcwp clr    <dev> <lba>        CMD29 CLR_WRITE_PROT
 *   mmcwp c      <dev> <opcode> <arg> [data]
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define O_RDWR 2

extern int printf(const char *fmt, ...);
extern void *memset(void *s, int c, u32 n);
extern int open(const char *path, int flags, ...);
extern int close(int fd);
extern int ioctl(int fd, unsigned long req, ...);
extern int strcmp(const char *a, const char *b);
extern void exit(int code) __attribute__((noreturn));
extern int *__errno(void);
#define errno (*__errno())

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
	u64  data_ptr;
};

#define MMC_RSP_PRESENT (1u<<0)
#define MMC_RSP_CRC     (1u<<2)
#define MMC_RSP_BUSY    (1u<<3)
#define MMC_RSP_OPCODE  (1u<<4)
#define MMC_CMD_ADTC    (1u<<5)
#define MMC_RSP_R1      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R1B     (MMC_RSP_R1|MMC_RSP_BUSY)
#define MMC_IOC_CMD 0xC048B300u

static u8 buf[4096];

static long long parse_hex(const char *p)
{
	long long v = 0;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;
	while (*p) {
		int d;
		char c = *p++;
		if (c >= '0' && c <= '9') d = c - '0';
		else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
		else break;
		v = v * 16 + d;
	}
	return v;
}

static int send(int fd, u32 opcode, u32 arg, int wr, u32 flags,
		u32 blksz, u32 blocks, void *data)
{
	struct mmc_ioc_cmd cmd;
	int r;

	memset(&cmd, 0, sizeof(cmd));
	cmd.write_flag = wr;
	cmd.opcode = opcode;
	cmd.arg = arg;
	cmd.flags = flags;
	cmd.blksz = blksz;
	cmd.blocks = blocks;
	cmd.data_timeout_ns = 0x20000000;
	cmd.cmd_timeout_ms = 10000;
	cmd.data_ptr = (u64)(unsigned long)data;
	r = ioctl(fd, MMC_IOC_CMD, &cmd);
	printf("CMD%u arg=0x%x -> %d errno=%d rsp=%08x %08x %08x %08x\n",
	       opcode, arg, r, errno, cmd.response[0], cmd.response[1],
	       cmd.response[2], cmd.response[3]);
	return r;
}

int main(int argc, char **argv)
{
	int fd;
	const char *mode;

	if (argc < 3) {
		printf("usage: mmcwp csd|extcsd|get|set|clr|c ...\n");
		return 2;
	}
	mode = argv[1];
	fd = open(argv[2], O_RDWR);
	if (fd < 0) {
		printf("open %s failed (errno %d)\n", argv[2], errno);
		return 1;
	}
	if (!strcmp(mode, "csd")) {
		memset(buf, 0, 16);
		send(fd, 9, 0, 0, MMC_RSP_R1, 16, 1, buf);
		for (int i = 0; i < 16; i++)
			printf("%02x%c", buf[i], (i % 16 == 15) ? '\n' : ' ');
	} else if (!strcmp(mode, "extcsd")) {
		memset(buf, 0, 512);
		send(fd, 8, 0, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, buf);
		if (argc > 3) {
			int f = open(argv[3], 0x241 /*O_WRONLY|O_CREAT|O_TRUNC*/,
				     0644);
			if (f >= 0) {
				extern int write(int, const void *, u32);
				write(f, buf, 512);
				close(f);
			}
		}
		printf("WP_GRP_SIZE[224]=%u  BOOT_WP[173]=0x%02x  "
		       "WR_PROTECT[166]=0x%02x  EXT_CSD_REV=%u\n",
		       buf[224], buf[173], buf[166], buf[192]);
	} else if (!strcmp(mode, "get")) {
		u32 lba = (u32)parse_hex(argv[3]);
		memset(buf, 0, 8);
		send(fd, 30, lba, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 4, 1, buf);
		printf("write-protect bits at lba %u: %02x %02x %02x %02x\n",
		       lba, buf[0], buf[1], buf[2], buf[3]);
	} else if (!strcmp(mode, "set")) {
		send(fd, 28, (u32)parse_hex(argv[3]), 0, MMC_RSP_R1B, 0, 0, 0);
	} else if (!strcmp(mode, "clr")) {
		send(fd, 29, (u32)parse_hex(argv[3]), 0, MMC_RSP_R1B, 0, 0, 0);
	} else if (!strcmp(mode, "wpw")) {
		/* CMD6: write EXT_CSD byte 166 (WRITE_PROTECT) */
		u32 val = (u32)parse_hex(argv[3]);
		u32 arg = (0x03u << 24) | (166u << 16) | ((val & 0xffu) << 8) | 0x03u;
		send(fd, 6, arg, 0, MMC_RSP_R1B, 0, 0, 0);
		memset(buf, 0, 512);
		send(fd, 8, 0, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, buf);
		printf("after write: WRITE_PROTECT[166]=0x%02x WP_GRP_SIZE=%u\n",
		       buf[166], buf[224]);
	} else if (!strcmp(mode, "c")) {
		u32 op = (u32)parse_hex(argv[3]);
		u32 arg = (u32)parse_hex(argv[4]);
		send(fd, op, arg, 0, MMC_RSP_R1, 0, 0, 0);
	}
	close(fd);
	return 0;
}

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
	__asm__ volatile("mov r0, sp\n\tb start_c\n");
}
