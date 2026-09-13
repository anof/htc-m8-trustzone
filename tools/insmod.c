/* insmod_raw - call init_module(2) directly, bypassing toybox's insmod.
 *
 * usage: insmod_raw <module.ko>
 * Freestanding: reads the file, then syscall 128 (__NR_init_module on ARM EABI).
 */

typedef unsigned int u32;

#define SYS_EXIT   1
#define SYS_READ   3
#define SYS_WRITE  4
#define SYS_OPEN   5
#define SYS_CLOSE  6
#define SYS_INIT_MODULE 128

static int sc3(int n, long a, long b, long c)
{
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r7 __asm__("r7") = n;
    __asm__ volatile ("svc 0" : "+r" (r0)
                      : "r" (r1), "r" (r2), "r" (r7) : "memory");
    return (int)r0;
}
static int sc1(int n, long a) { return sc3(n, a, 0, 0); }

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static int puts_(const char *s) { return sc3(SYS_WRITE, 1, (long)s, slen(s)); }
static void puthex(u32 v, int d)
{
    char b[12];
    const char *h = "0123456789abcdef";
    int i;
    for (i = 0; i < d; i++) b[i] = h[(v >> ((d - 1 - i) * 4)) & 0xf];
    sc3(SYS_WRITE, 1, (long)b, d);
}

/* 16 MB is plenty for a .ko */
static char buf[16 * 1024 * 1024];

void _start(void)
{
    long *sp;
    __asm__ volatile ("mov %0, sp" : "=r" (sp));
    int argc = (int)sp[0];
    char **argv = (char **)(sp + 1);

    if (argc < 2) {
        static char *defv[] = { "insmod_raw", "/data/local/tmp/tzctl.ko" };
        argv = defv; argc = 2;
    }

    int fd = sc3(SYS_OPEN, (long)argv[1], 0 /*O_RDONLY*/, 0);
    if (fd < 0) { puts_("open failed\n"); sc1(SYS_EXIT, 2); }

    long total = 0;
    for (;;) {
        int n = sc3(SYS_READ, fd, (long)(buf + total), (long)(sizeof(buf) - total));
        if (n <= 0) break;
        total += n;
    }
    sc1(SYS_CLOSE, fd);

    puts_("read "); puthex((u32)total, 8); puts_(" bytes\n");

    int r = sc3(SYS_INIT_MODULE, (long)buf, total, (long)"");
    puts_("init_module -> "); puthex((u32)r, 8); puts_("\n");
    sc1(SYS_EXIT, 0);
}
