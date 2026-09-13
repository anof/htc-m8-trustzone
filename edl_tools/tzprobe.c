/* tzprobe - enumerate / probe / fuzz a QSEE trustlet command surface.
 *
 * usage:
 *   tzprobe enum <path> <app> <lo> <hi> [reqsz] [rspsz]
 *   tzprobe send <path> <app> <cmd> <hexpayload> [rspsz]
 *   tzprobe fuzz <path> <app> <cmd> <iters> [reqsz] [rspsz] [seed]
 *
 * All buffers are ION-backed (same pattern as the working keymaster PoC).
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern int printf(const char *fmt, ...);
extern void *memset(void *s, int c, u32 n);
extern void *memcpy(void *d, const void *s, u32 n);
extern int strcmp(const char *a, const char *b);
extern unsigned long strtoul(const char *s, char **end, int base);
extern int open(const char *path, int flags, ...);
extern int ioctl(int fd, unsigned long req, ...);
extern void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
extern int close(int fd);
extern int usleep(unsigned int us);
extern int *__errno(void);
extern void exit(int code) __attribute__((noreturn));
#define errno (*__errno())

#define O_RDONLY 0
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_FAILED ((void *)-1)

struct ion_allocation_data { u32 len, align, heap_mask, flags; void *handle; };
struct ion_fd_data { void *handle; int fd; };
#define ION_IOC_ALLOC 0xC0144900u
#define ION_IOC_MAP 0xC0084902u

struct QSEECom_handle;
extern int QSEECom_start_app(struct QSEECom_handle **h, const char *path,
			     const char *app_name, u32 size);
extern int QSEECom_shutdown_app(struct QSEECom_handle **h);
extern int QSEECom_send_cmd(struct QSEECom_handle *h, void *send_buf,
			    u32 send_len, void *resp_buf, u32 resp_len);

static int ion_fd = -1;

static void *ion_alloc(u32 size, int *fd_out)
{
	struct ion_allocation_data alloc;
	struct ion_fd_data fd_data;
	void *va;

	memset(&alloc, 0, sizeof(alloc));
	alloc.len = size;
	alloc.align = 4096;
	alloc.heap_mask = (1u << 27);
	if (ioctl(ion_fd, ION_IOC_ALLOC, &alloc) < 0) {
		printf("ION alloc failed errno=%d\n", errno);
		return 0;
	}
	memset(&fd_data, 0, sizeof(fd_data));
	fd_data.handle = alloc.handle;
	if (ioctl(ion_fd, ION_IOC_MAP, &fd_data) < 0) {
		printf("ION map failed errno=%d\n", errno);
		return 0;
	}
	va = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_data.fd, 0);
	if (va == MAP_FAILED) {
		printf("ION mmap failed errno=%d\n", errno);
		return 0;
	}
	*fd_out = fd_data.fd;
	return va;
}

static u32 seed = 0x12345678;
static u32 rnd(void)
{
	seed = seed * 1103515245u + 12345u;
	return seed;
}

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
	__asm__ volatile("mov r0, sp\n\tb start_c\n\t");
}

static int hex2bin(const char *s, u8 *out, u32 max)
{
	u32 n = 0;
	while (s[0] && s[1] && n < max) {
		u32 v = 0;
		int i;
		for (i = 0; i < 2; i++) {
			char c = s[i];
			v <<= 4;
			if (c >= '0' && c <= '9') v |= c - '0';
			else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
		}
		out[n++] = (u8)v;
		s += 2;
	}
	return (int)n;
}

int main(int argc, char **argv)
{
	const char *mode, *path, *app;
	struct QSEECom_handle *h = 0;
	u8 *req, *rsp;
	int reqfd, rspfd;
	u32 reqsz = 4096, rspsz = 4096, lo, hi, cmd, iters = 1, i;
	int r;

	if (argc < 5) {
		printf("usage: tzprobe enum|send|fuzz <path> <app> ...\n");
		return 2;
	}
	mode = argv[1];
	path = argv[2];
	app = argv[3];

	ion_fd = open("/dev/ion", O_RDONLY);
	if (ion_fd < 0) { printf("open /dev/ion errno=%d\n", errno); return 1; }

	req = (u8 *)ion_alloc(0x20000, &reqfd);
	rsp = (u8 *)ion_alloc(0x20000, &rspfd);
	if (!req || !rsp) return 1;
	/* QSEECom convention: the reply lands in the *same* shared buffer,
	 * at the first aligned offset after the request. Use one buffer. */
	(void)rspfd;

	{
		u32 asz = 4096 * 4;
		if (argc > 9) asz = (u32)strtoul(argv[9], 0, 0);
		r = QSEECom_start_app(&h, path, app, asz);
		printf("start_app(%s, %s, %u) -> %d (errno %d)\n",
		       path, app, asz, r, errno);
	}
	if (r) return 1;

	if (!strcmp(mode, "enum")) {
		lo = (u32)strtoul(argv[4], 0, 0);
		hi = (u32)strtoul(argv[5], 0, 0);
		if (argc > 6) reqsz = (u32)strtoul(argv[6], 0, 0);
		if (argc > 7) rspsz = (u32)strtoul(argv[7], 0, 0);
		for (cmd = lo; cmd <= hi; cmd++) {
			u8 *rp;
			memset(req, 0, reqsz);
			*(u32 *)req = cmd;
			rp = req + ((reqsz + 0x3f) & ~0x3fu);
			memset(rp, 0, rspsz);
			r = QSEECom_send_cmd(h, req, (reqsz + 0x3f) & ~0x3fu, rp, rspsz);
			if (r != -1 /* -EPERM/EINVAL for unknown */)
				printf("cmd %#010x -> %d  rsp[0..3]=%08x %08x\n",
				       cmd, r, *(u32 *)(rp), *(u32 *)(rp + 4));
			usleep(1000);
		}
	} else if (!strcmp(mode, "send")) {
		u8 *rp;
		cmd = (u32)strtoul(argv[4], 0, 0);
		memset(req, 0, reqsz);
		*(u32 *)req = cmd;
		{
			int n = 0;
			if (argc > 5) n = hex2bin(argv[5], req + 4, reqsz - 4);
			if (argc > 6) rspsz = (u32)strtoul(argv[6], 0, 0);
			reqsz = 4 + n;
			rp = req + ((reqsz + 0x3f) & ~0x3fu);
			memset(rp, 0, rspsz);
			printf("sending cmd=%#x len=%u\n", cmd, reqsz);
			r = QSEECom_send_cmd(h, req, (reqsz + 0x3f) & ~0x3fu, rp, rspsz);
			printf("-> %d  rsp: %08x %08x %08x %08x\n", r,
			       *(u32 *)rp, *(u32 *)(rp + 4),
			       *(u32 *)(rp + 8), *(u32 *)(rp + 12));
		}
	} else if (!strcmp(mode, "fuzz")) {
		u8 *rp;
		cmd = (u32)strtoul(argv[4], 0, 0);
		iters = (u32)strtoul(argv[5], 0, 0);
		if (argc > 6) reqsz = (u32)strtoul(argv[6], 0, 0);
		if (argc > 7) rspsz = (u32)strtoul(argv[7], 0, 0);
		if (argc > 8) seed = (u32)strtoul(argv[8], 0, 0);
		for (i = 0; i < iters; i++) {
			u32 j;
			memset(req, 0, reqsz);
			*(u32 *)req = cmd;
			for (j = 4; j < reqsz; j++) req[j] = (u8)rnd();
			rp = req + ((reqsz + 0x3f) & ~0x3fu);
			r = QSEECom_send_cmd(h, req, (reqsz + 0x3f) & ~0x3fu, rp, rspsz);
			if (i % 25 == 0)
				printf("iter %u -> %d (rsp %08x)\n", i, r, *(u32 *)rp);
		}
	} else if (!strcmp(mode, "smart")) {
		/* Structured fuzzing: for every 4-byte word of the parameter
		 * area, try extreme values while keeping the rest zero. */
		u8 *rp;
		u32 j, k;
		static const u32 vals[] = {
			0x00000000u, 0x00000001u, 0x0000ffffu, 0x00010000u,
			0x7fffffffu, 0x80000000u, 0xffffffffu, 0xdeadbeefu,
			0x41414141u, 0x0da10000u,
		};
		cmd = (u32)strtoul(argv[4], 0, 0);
		if (argc > 5) reqsz = (u32)strtoul(argv[5], 0, 0);
		if (argc > 6) rspsz = (u32)strtoul(argv[6], 0, 0);
		printf("smart: cmd=%#x reqsz=%u rspsz=%u\n", cmd, reqsz, rspsz);
		for (j = 4; j + 4 <= reqsz; j += 4) {
			for (k = 0; k < sizeof(vals) / sizeof(vals[0]); k++) {
				memset(req, 0, reqsz);
				*(u32 *)req = cmd;
				*(u32 *)(req + j) = vals[k];
				rp = req + ((reqsz + 0x3f) & ~0x3fu);
				memset(rp, 0, rspsz);
				r = QSEECom_send_cmd(h, req, (reqsz + 0x3f) & ~0x3fu,
						     rp, rspsz);
				if (r != 0 || *(u32 *)rp != 0)
					printf("  off %#x val %#x -> %d rsp %08x %08x\n",
					       j, vals[k], r, *(u32 *)rp,
					       *(u32 *)(rp + 4));
			}
		}
		printf("smart done\n");
	}
	if (h) QSEECom_shutdown_app(&h);
	return 0;
}
