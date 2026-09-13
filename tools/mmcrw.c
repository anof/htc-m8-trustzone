/* mmcrw - raw eMMC single/multi block read-write via MMC_IOC_CMD.
 * Bypasses the block layer entirely: talks straight to the card.
 *
 * usage:
 *   mmcrw r <dev> <lba> <blocks>        read + hexdump first 64 bytes
 *   mmcrw w <dev> <lba> <hexstring>     write one 512B block (hex, rest 0)
 *   mmcrw x <dev> <lba> <blocks> <file> read blocks into file (raw)
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

#define NULL ((void *)0)
#define O_RDONLY 0
#define O_RDWR 2

extern int printf(const char *fmt, ...);
extern void *memset(void *s, int c, u32 n);
extern int open(const char *path, int flags, ...);
extern int close(int fd);
extern int ioctl(int fd, unsigned long req, ...);
extern int write(int fd, const void *buf, u32 n);
extern int read(int fd, void *buf, u32 n);
extern int strcmp(const char *a, const char *b);
extern u32 strlen(const char *s);
extern int sscanf(const char *s, const char *fmt, ...);
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
#define MMC_RSP_OPCODE  (1u<<4)
#define MMC_CMD_ADTC    (1u<<5)
#define MMC_RSP_R1      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_IOC_CMD 0xC048B300u

static u8 buf[64 * 1024];

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
	__asm__ volatile("mov r0, sp\n\tb start_c\n");
}

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

static int do_cmd(int fd, u32 opcode, u32 arg, int wr, u32 blocks, void *data)
{
	struct mmc_ioc_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.write_flag = wr;
	cmd.is_acmd = 0;
	cmd.opcode = opcode;
	cmd.arg = arg;
	cmd.flags = MMC_RSP_R1 | MMC_CMD_ADTC;
	cmd.blksz = 512;
	cmd.blocks = blocks;
	cmd.data_timeout_ns = 0x20000000;
	cmd.data_ptr = (u64)(unsigned long)data;
	int r = ioctl(fd, MMC_IOC_CMD, &cmd);
	if (r < 0)
		printf("  CMD%u errno=%d rsp=%08x %08x\n", opcode, errno,
		       cmd.response[0], cmd.response[1]);
	return r;
}

int main(int argc, char **argv)
{
	const char *mode, *dev;
	long long lba;
	int fd;

	if (argc < 4) {
		printf("usage: mmcrw r|w|x ...\n");
		return 2;
	}
	mode = argv[1];
	dev = argv[2];
	lba = parse_hex(argv[3]);

	if (!strcmp(mode, "r")) {
		long blocks = argc > 4 ? (long)parse_hex(argv[4]) : 1;
		if (blocks < 1 || blocks > 128) blocks = 1;
		fd = open(dev, O_RDONLY);
		if (fd < 0) { printf("open errno=%d\n", errno); return 1; }
		memset(buf, 0, 512);
		int r = do_cmd(fd, blocks == 1 ? 17 : 18, (u32)lba, 0, blocks, buf);
		close(fd);
		if (r < 0) return 1;
		printf("read %ld block(s) @ lba %lld:\n", blocks, lba);
		for (int i = 0; i < 64; i++) {
			printf("%02x", buf[i]);
			if ((i & 15) == 15) printf("\n");
		}
		return 0;
	}
	if (!strcmp(mode, "w")) {
		const char *hex = argv[4];
		u32 n = strlen(hex) / 2;
		if (n > 512) n = 512;
		memset(buf, 0, 512);
		for (u32 i = 0; i < n; i++) {
			unsigned v = 0;
			sscanf(hex + 2 * i, "%2x", &v);
			buf[i] = (u8)v;
		}
		fd = open(dev, O_RDWR);
		if (fd < 0) { printf("open errno=%d\n", errno); return 1; }
		int r = do_cmd(fd, 24, (u32)lba, 1, 1, buf);
		printf("write %s\n", r < 0 ? "FAILED" : "accepted");
		close(fd);
		return 0;
	}
	if (!strcmp(mode, "x")) {
		long blocks = (long)parse_hex(argv[4]);
		fd = open(dev, O_RDONLY);
		if (fd < 0) { printf("open errno=%d\n", errno); return 1; }
		int r = do_cmd(fd, 18, (u32)lba, 0, (u32)blocks, buf);
		close(fd);
		if (r < 0) { printf("raw read failed\n"); return 1; }
		int ofd = open(argv[5], 1 | 0100 /* O_WRONLY|O_CREAT */, 0644);
		if (ofd >= 0) {
			write(ofd, buf, (u32)blocks * 512);
			close(ofd);
			printf("wrote %ld blocks to %s\n", blocks, argv[5]);
		}
		return 0;
	}
	printf("unknown mode\n");
	return 2;
}
