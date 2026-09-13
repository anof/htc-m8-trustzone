/* rmmod_raw - unload the "tzmod" module via delete_module(2) directly.
 *
 * A naked entry stub is used to capture the initial sp reliably: with a
 * normal C function the prologue can adjust sp before the read, which is
 * why the earlier insmod_raw always fell back to its hardcoded path.
 */

#define SYS_EXIT          1
#define SYS_WRITE         4
#define SYS_DELETE_MODULE 129

static int sc2(int n, long a, long b)
{
	register long r0 __asm__("r0") = a;
	register long r1 __asm__("r1") = b;
	register long r7 __asm__("r7") = n;
	__asm__ volatile ("svc 0" : "+r" (r0)
			  : "r" (r1), "r" (r7) : "memory");
	return (int)r0;
}

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static int puts_(const char *s) { return sc2(SYS_WRITE, 1, (long)s); }
static void puthex(unsigned int v)
{
	char b[8];
	const char *h = "0123456789abcdef";
	int i;
	for (i = 0; i < 8; i++) b[i] = h[(v >> ((7 - i) * 4)) & 0xf];
	sc2(SYS_WRITE, 1, (long)b);
}

void _start(void) __attribute__((naked));
void _start(void)
{
	__asm__ volatile (
		"mov r0, sp\n\t"
		"bl  notmain\n\t"
		"mov r7, #1\n\t"
		"mov r0, #0\n\t"
		"svc 0\n\t");
}

void notmain(long *sp)
{
	(void)sp;
	int r = sc2(SYS_DELETE_MODULE, (long)"tzmod", 0);
	puts_("delete_module(tzmod) -> ");
	puthex((unsigned int)r);
	puts_("\n");
	(void)slen;
}
