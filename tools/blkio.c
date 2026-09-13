/* blkio - precise block-device pread/pwrite with errno reporting.
 * Freestanding (no target headers); links against the device's libc.
 *
 * usage:
 *   blkio ro <dev>
 *   blkio r  <dev> <off> <len>
 *   blkio w  <dev> <off> <hexstring>
 *   blkio f  <dev> <off> <file>
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long ssize_t;

#define NULL ((void *)0)
#define O_RDONLY 0
#define O_RDWR 2
#define BLKROGET 0x1257
#define SEEK_END 2
#define SEEK_SET 0

extern int printf(const char *fmt, ...);
extern void *malloc(u32 n);
extern int open(const char *path, int flags, ...);
extern int close(int fd);
extern ssize_t read(int fd, void *buf, u32 n);
extern ssize_t pread(int fd, void *buf, u32 n, long off);
extern ssize_t pwrite(int fd, const void *buf, u32 n, long off);
extern long lseek(int fd, long off, int whence);
extern int fsync(int fd);
extern int ioctl(int fd, unsigned long req, ...);
extern int strcmp(const char *a, const char *b);
extern u32 strlen(const char *s);
extern int sscanf(const char *s, const char *fmt, ...);
extern void exit(int code) __attribute__((noreturn));
extern int *__errno(void);
#define errno (*__errno())

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

static void hexdump(const u8 *b, long n)
{
	for (long i = 0; i < n; i++) {
		printf("%02x", b[i]);
		if ((i & 31) == 31)
			printf("\n");
	}
	printf("\n");
}

static long long parse_hex(const char *p)
{
	long long v = 0;
	int neg = 0;
	if (*p == '-') { neg = 1; p++; }
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
	return neg ? -v : v;
}

int main(int argc, char **argv)
{
	const char *mode, *dev;
	int fd;
	long long off;

	if (argc < 3) {
		printf("usage: blkio ro|r|w|f ...\n");
		return 2;
	}
	mode = argv[1];
	dev = argv[2];

	if (!strcmp(mode, "ro")) {
		int ro = -1;
		fd = open(dev, O_RDONLY);
		if (fd < 0) {
			printf("open errno=%d\n", errno);
			return 1;
		}
		int r = ioctl(fd, BLKROGET, &ro);
		printf("BLKROGET rc=%d ro=%d\n", r, ro);
		close(fd);
		return 0;
	}
	if (argc < 5) {
		printf("need offset and payload\n");
		return 2;
	}
	off = parse_hex(argv[3]);

	if (!strcmp(mode, "r")) {
		long len = (long)parse_hex(argv[4]);
		u8 *b = malloc(len ? (u32)len : 1);
		fd = open(dev, O_RDONLY);
		if (fd < 0) { printf("open errno=%d\n", errno); return 1; }
		ssize_t got = pread(fd, b, (u32)len, off);
		printf("pread rc=%ld errno=%d\n", (long)got, errno);
		hexdump(b, got > 0 ? got : 0);
		close(fd);
		return 0;
	}
	if (!strcmp(mode, "w")) {
		const char *hex = argv[4];
		u32 hl = strlen(hex);
		u32 n = hl / 2;
		u8 *b = malloc(n ? n : 1);
		for (u32 i = 0; i < n; i++) {
			unsigned v = 0;
			sscanf(hex + 2 * i, "%2x", &v);
			b[i] = (u8)v;
		}
		fd = open(dev, O_RDWR);
		if (fd < 0) { printf("open errno=%d\n", errno); return 1; }
		ssize_t w = pwrite(fd, b, n, off);
		printf("pwrite rc=%ld want=%u errno=%d\n", (long)w, n, errno);
		int s = fsync(fd);
		printf("fsync rc=%d errno=%d\n", s, errno);
		close(fd);
		return 0;
	}
	if (!strcmp(mode, "f")) {
		fd = open(argv[4], O_RDONLY);
		if (fd < 0) { printf("open payload errno=%d\n", errno); return 1; }
		u64 n = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		u8 *b = malloc(n ? (u32)n : 1);
		ssize_t got = read(fd, b, (u32)n);
		close(fd);
		printf("payload %ld bytes\n", (long)got);
		fd = open(dev, O_RDWR);
		if (fd < 0) { printf("open dev errno=%d\n", errno); return 1; }
		ssize_t w = pwrite(fd, b, (u32)got, off);
		printf("pwrite rc=%ld want=%ld errno=%d\n", (long)w, (long)got, errno);
		int s = fsync(fd);
		printf("fsync rc=%d errno=%d\n", s, errno);
		close(fd);
		return 0;
	}
	printf("unknown mode\n");
	return 2;
}
