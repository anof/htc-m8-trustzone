/* insmod_mmap - load a module by mmap()ing the file instead of read()ing it.
 *
 * usage: insmod_mmap <module.ko>
 * Freestanding ARM: open, lseek(size), mmap(PROT_READ), init_module(2).
 */
typedef unsigned int u32;

#define SYS_EXIT        1
#define SYS_READ        3
#define SYS_WRITE       4
#define SYS_OPEN        5
#define SYS_CLOSE       6
#define SYS_LSEEK       19
#define SYS_MMAP        192
#define SYS_INIT_MODULE 128

#define O_RDONLY   0
#define SEEK_END   2
#define PROT_READ  1
#define MAP_PRIVATE 2

static int sc(int n, long a, long b, long c, long d, long e, long f)
{
	register long r0 __asm__("r0") = a;
	register long r1 __asm__("r1") = b;
	register long r2 __asm__("r2") = c;
	register long r3 __asm__("r3") = d;
	register long r4 __asm__("r4") = e;
	register long r5 __asm__("r5") = f;
	register long r7 __asm__("r7") = n;
	__asm__ volatile ("svc 0" : "+r" (r0)
			  : "r" (r1), "r" (r2), "r" (r3), "r" (r4), "r" (r5),
			    "r" (r7) : "memory");
	return (int)r0;
}

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static int puts_(const char *s) { return sc(SYS_WRITE, 1, (long)s, slen(s), 0, 0, 0); }
static void puthex(u32 v)
{
	char b[8];
	const char *h = "0123456789abcdef";
	int i;
	for (i = 0; i < 8; i++) b[i] = h[(v >> ((7 - i) * 4)) & 0xf];
	sc(SYS_WRITE, 1, (long)b, 8, 0, 0, 0);
}

void start_c(long *sp) __attribute__((used));
void start_c(long *sp)
{
	int argc = (int)sp[0];
	char **argv = (char **)(sp + 1);
	int fd, size;
	void *map;

	if (argc < 2) {
		puts_("usage: insmod_mmap <module.ko>\n");
		sc(SYS_EXIT, 2, 0, 0, 0, 0, 0);
	}
	fd = sc(SYS_OPEN, (long)argv[1], O_RDONLY, 0, 0, 0, 0);
	if (fd < 0) { puts_("open failed\n"); sc(SYS_EXIT, 2, 0, 0, 0, 0, 0); }
	size = sc(SYS_LSEEK, fd, 0, SEEK_END, 0, 0, 0);
	puts_("size "); puthex((u32)size); puts_("\n");
	if (size <= 0) { puts_("bad size\n"); sc(SYS_EXIT, 2, 0, 0, 0, 0, 0); }
	map = (void *)sc(SYS_MMAP, 0, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if ((unsigned long)map >= (unsigned long)-4095) {
		puts_("mmap failed\n");
		sc(SYS_EXIT, 2, 0, 0, 0, 0, 0);
	}
	puts_("map "); puthex((u32)(unsigned long)map); puts_("\n");
	int r = sc(SYS_INIT_MODULE, (long)map, size, (long)"", 0, 0, 0);
	puts_("init_module -> "); puthex((u32)r); puts_("\n");
	sc(SYS_EXIT, 0, 0, 0, 0, 0, 0);
}

void _start(void) __attribute__((naked));
void _start(void)
{
	__asm__ volatile("mov r0, sp\n\tb start_c\n");
}
