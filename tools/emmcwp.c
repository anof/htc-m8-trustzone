/* emmcwp - HTC M8 eMMC write-protect inspector / unlocker / S-OFF flag writer.
 *
 * Background: hboot arms the card's per-WP-group write protection
 * (SET_WRITE_PROT / CMD28) over the firmware partitions on every boot, and
 * the card then *accepts* writes to those LBAs and throws the data away.
 * The WP type is selected by EXT_CSD[171] (USER_WP):
 *
 *      PERM_WP_EN  PWR_WP_EN    type set by CMD28
 *         0            0        temporary     <- cleared by CMD29 / power cycle
 *         0            1        power-on      <- cleared by clearing PWR_WP_EN
 *         1            x        permanent     <- cannot be cleared
 *
 * SEND_WRITE_PROT_TYPE (CMD31) reports that type per group, which is the
 * measurement that decides whether this device can be unlocked from the AP
 * at all.  All commands report the card's R1 status word, so a rejected
 * write shows up as WP_VIOLATION (bit 26) instead of silently going missing.
 *
 * usage:
 *   emmcwp info                    EXT_CSD: USER_WP, group size, BOOT_WP ...
 *   emmcwp type  <lba> [ngroups]   CMD31: WP type of each 16 MB group
 *   emmcwp wp    <lba>             CMD30: WP bits
 *   emmcwp clr   <lba>             CMD29: CLEAR_WRITE_PROT for that group
 *   emmcwp set   <lba>             CMD28: SET_WRITE_PROT for that group
 *   emmcwp usrwp <mode> <val>      CMD6 on EXT_CSD[171]  (mode 0=write,1=set,2=clr)
 *   emmcwp rd    <lba> [blocks]    read + hexdump
 *   emmcwp rdf   <lba> <blocks> <file>
 *   emmcwp wtest <lba>             write/verify/restore one sector
 *   emmcwp flagread                read LBA 2148 (pg1fs_security[0])
 *   emmcwp flagsoff                flip it to S-OFF (0), verify, backup
 *   emmcwp seq                     full non-destructive diagnosis
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
extern int usleep(unsigned int us);

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

#define MMC_RSP_PRESENT (1u << 0)
#define MMC_RSP_136     (1u << 1)
#define MMC_RSP_CRC     (1u << 2)
#define MMC_RSP_BUSY    (1u << 3)
#define MMC_RSP_OPCODE  (1u << 4)
#define MMC_CMD_ADTC    (1u << 5)
#define MMC_RSP_R1      (MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE)
#define MMC_RSP_R1B     (MMC_RSP_R1 | MMC_RSP_BUSY)
#define MMC_RSP_R2      (MMC_RSP_PRESENT | MMC_RSP_136 | MMC_RSP_CRC)
#define MMC_IOC_CMD     0xC048B300u

/* EXT_CSD indices (eMMC 4.5) */
#define EXT_CSD_REV              192
#define EXT_CSD_PART_SUPPORT     160
#define EXT_CSD_PART_ATTR        156
#define EXT_CSD_USER_WP          171
#define EXT_CSD_BOOT_WP          173
#define EXT_CSD_BOOT_WP_STATUS   174
#define EXT_CSD_ERASE_GROUP_DEF  175
#define EXT_CSD_HC_WP_GRP_SIZE   221
#define EXT_CSD_HC_ERASE_GRP_SZ  224
#define EXT_CSD_SEC_COUNT        212

/* USER_WP bits */
#define US_PWR_WP_EN   0x01
#define US_PERM_WP_EN  0x02
#define US_PWR_WP_DIS  0x04
#define US_PERM_WP_DIS 0x08

#define FLAG_LBA 2148          /* pg1fs start 2082 + 0x8400/512 */
#define SCRATCH_LBA 4130       /* pg1fs + 1 MiB: unused, same WP group   */

static u8 buf[64 * 1024];
static const char *DEV = "/dev/block/mmcblk0";
static int g_verbose = 1;

static long long parse_num(const char *p)
{
	long long v = 0;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		p += 2;
		while (*p) {
			int d; char c = *p++;
			if (c >= '0' && c <= '9') d = c - '0';
			else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
			else break;
			v = v * 16 + d;
		}
		return v;
	}
	while (*p >= '0' && *p <= '9')
		v = v * 10 + (*p++ - '0');
	return v;
}

static void r1_decode(u32 r)
{
	printf("  r1=%08x", r);
	if (r & (1u << 31)) printf(" ADDR_OUT_OF_RANGE");
	if (r & (1u << 30)) printf(" ADDR_MISALIGN");
	if (r & (1u << 29)) printf(" BLOCK_LEN_ERR");
	if (r & (1u << 28)) printf(" ERASE_SEQ_ERR");
	if (r & (1u << 27)) printf(" ERASE_PARAM");
	if (r & (1u << 26)) printf(" WP_VIOLATION");
	if (r & (1u << 25)) printf(" CARD_LOCKED");
	if (r & (1u << 24)) printf(" LOCK_UNLOCK_FAILED");
	if (r & (1u << 22)) printf(" ILLEGAL_COMMAND");
	if (r & (1u << 20)) printf(" CC_ERROR");
	if (r & (1u << 19)) printf(" ERROR");
	if (r & (1u << 15)) printf(" WP_ERASE_SKIP");
	if (r & (1u << 7)) printf(" SWITCH_ERROR");
	printf("  state=%u\n", (r >> 9) & 0xf);
}

/* generic command; returns ioctl rc, prints r1 */
static int cmd(int fd, u32 opcode, u32 arg, int wr, u32 flags,
	       u32 blksz, u32 blocks, void *data, const char *what,
	       u32 *r1out)
{
	struct mmc_ioc_cmd c;
	int r;

	memset(&c, 0, sizeof(c));
	c.write_flag = wr;
	c.opcode = opcode;
	c.arg = arg;
	c.flags = flags;
	c.blksz = blksz;
	c.blocks = blocks;
	c.data_timeout_ns = 0x20000000;
	c.cmd_timeout_ms = 5000;
	c.data_ptr = (u64)(unsigned long)data;
	r = ioctl(fd, MMC_IOC_CMD, &c);
	if (g_verbose) {
		printf("CMD%-2u arg=%#010x -> %d", opcode, arg, r);
		if (what)
			printf("  [%s]", what);
		printf("\n");
		r1_decode(c.response[0]);
	}
	if (r1out)
		*r1out = c.response[0];
	if (g_verbose && (c.response[1] || c.response[2] || c.response[3]))
		printf("  rsp1=%08x rsp2=%08x rsp3=%08x\n",
		       c.response[1], c.response[2], c.response[3]);
	return r;
}

static int wait_tran(int fd)
{
	u32 r1 = 0;
	int i;
	int save = g_verbose;
	g_verbose = 0;
	for (i = 0; i < 200; i++) {
		if (cmd(fd, 13, 0, 0, MMC_RSP_R1, 0, 0, NULL, "CMD13", &r1) < 0)
			break;
		if (((r1 >> 9) & 0xf) == 4)
			break;
		usleep(20000);
	}
	g_verbose = save;
	return (((r1 >> 9) & 0xf) == 4) ? 0 : -1;
}

static int read_extcsd(int fd, u8 *out)
{
	memset(out, 0, 512);
	if (cmd(fd, 8, 0, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, out,
		"EXT_CSD", NULL) < 0)
		return -1;
	return 0;
}

static u32 wp_group_size(const u8 *e)
{
	u32 s = (512u * 1024u) * e[EXT_CSD_HC_WP_GRP_SIZE] *
		e[EXT_CSD_HC_ERASE_GRP_SZ];
	return s / 512;
}

static void print_userwp(u8 v)
{
	printf("  USER_WP[%d] = 0x%02x  PWR_WP_EN=%d PERM_WP_EN=%d "
	       "PWR_WP_DIS=%d PERM_WP_DIS=%d\n",
	       EXT_CSD_USER_WP, v, !!(v & US_PWR_WP_EN), !!(v & US_PERM_WP_EN),
	       !!(v & US_PWR_WP_DIS), !!(v & US_PERM_WP_DIS));
	if ((v & US_PERM_WP_EN))
		printf("  !! PERM_WP_EN set: CMD28 groups are PERMANENT\n");
	else if ((v & US_PWR_WP_EN))
		printf("  -> CMD28 groups are POWER-ON type (clear PWR_WP_EN first)\n");
	else
		printf("  -> CMD28 groups are TEMPORARY type (CMD29 clears)\n");
}

static int do_info(int fd)
{
	u8 e[512];
	u32 sc;

	if (read_extcsd(fd, e) < 0)
		return -1;
	sc = e[EXT_CSD_SEC_COUNT] | (e[EXT_CSD_SEC_COUNT + 1] << 8) |
	     (e[EXT_CSD_SEC_COUNT + 2] << 16) |
	     ((u32)e[EXT_CSD_SEC_COUNT + 3] << 24);
	printf("EXT_CSD_REV=%u  dev size=%u MB  ERASE_GROUP_DEF=%u\n",
	       e[EXT_CSD_REV], (u32)((u64)sc * 512 / 1048576),
	       e[EXT_CSD_ERASE_GROUP_DEF]);
	print_userwp(e[EXT_CSD_USER_WP]);
	printf("  BOOT_WP[%d]=0x%02x BOOT_WP_STATUS[%d]=0x%02x\n",
	       EXT_CSD_BOOT_WP, e[EXT_CSD_BOOT_WP],
	       EXT_CSD_BOOT_WP_STATUS, e[EXT_CSD_BOOT_WP_STATUS]);
	printf("  HC_WP_GRP_SIZE[%d]=%u HC_ERASE_GRP_SIZE[%d]=%u\n",
	       EXT_CSD_HC_WP_GRP_SIZE, e[EXT_CSD_HC_WP_GRP_SIZE],
	       EXT_CSD_HC_ERASE_GRP_SZ, e[EXT_CSD_HC_ERASE_GRP_SZ]);
	printf("  => wp_group_size = %u sectors (%u MB)\n",
	       wp_group_size(e), wp_group_size(e) / 2048);
	printf("  flag group = %u, scratch group = %u\n",
	       FLAG_LBA / wp_group_size(e), SCRATCH_LBA / wp_group_size(e));
	{
		int f = open("/data/local/tmp/extcsd_now.bin",
			     0x241 /*O_WRONLY|O_CREAT|O_TRUNC*/, 0644);
		if (f >= 0) { write(f, e, 512); close(f);
			printf("  (saved to /data/local/tmp/extcsd_now.bin)\n"); }
	}
	return 0;
}

static int do_type(int fd, u32 lba, int ngroups)
{
	u8 t[8];
	u32 gs;
	u8 e[512];
	int i;

	if (read_extcsd(fd, e) < 0)
		return -1;
	gs = e[EXT_CSD_HC_WP_GRP_SIZE] * e[EXT_CSD_HC_ERASE_GRP_SZ] * 1024;
	memset(t, 0, sizeof(t));
	if (cmd(fd, 31, lba, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 8, 1, t,
		"WRITE_PROT_TYPE", NULL) < 0)
		return -1;
	printf("WP type bitmap (64-bit, 2 bits/group): "
	       "%02x %02x %02x %02x %02x %02x %02x %02x\n",
	       t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
	if (ngroups <= 0)
		ngroups = 16;
	for (i = 0; i < ngroups && i < 32; i++) {
		u8 byte = t[7 - (i / 4)];
		u32 ty = (byte >> (2 * (i % 4))) & 3;
		u32 start = (lba / gs + i) * gs;
		const char *nm = ty == 0 ? "none" : ty == 1 ? "TEMPORARY" :
				 ty == 2 ? "POWER-ON" : "PERMANENT";
		printf("  group %2d  lba %8u..%-8u  type=%u %s\n",
		       (int)(lba / gs) + i, start, start + gs - 1, ty, nm);
	}
	return 0;
}

static int do_wp(int fd, u32 lba)
{
	u8 w[4];
	memset(w, 0, sizeof(w));
	if (cmd(fd, 30, lba, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 4, 1, w,
		"SEND_WRITE_PROT", NULL) < 0)
		return -1;
	printf("  WP bits = %02x %02x %02x %02x\n", w[0], w[1], w[2], w[3]);
	return 0;
}

static int do_rd(int fd, u32 lba, int blocks, const char *file)
{
	int i;
	memset(buf, 0, 512);
	if (cmd(fd, blocks == 1 ? 17 : 18, lba, 0,
		MMC_RSP_R1 | MMC_CMD_ADTC, 512, blocks, buf, "read", NULL) < 0)
		return -1;
	if (file) {
		int f = open(file, 0x241, 0644);
		if (f >= 0) { write(f, buf, blocks * 512); close(f); }
	}
	for (i = 0; i < 32; i++) {
		printf("%02x", buf[i]);
		if ((i & 15) == 15) printf("\n");
	}
	return 0;
}

static int do_wr(int fd, u32 lba, const u8 *data, const char *what)
{
	u32 r1 = 0;
	if (cmd(fd, 24, lba, 1, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1,
		(void *)data, what, &r1) < 0)
		return -1;
	if (r1 & (1u << 26))
		printf("  ** WP_VIOLATION: the CARD rejected the write **\n");
	return 0;
}

/* write a pattern, read it back, restore original.  Returns 1 if the write
 * really landed, 0 if it was discarded, -1 on error. */
static int do_wtest(int fd, u32 lba)
{
	u8 orig[512], pat[512];
	int i, ok = 0;

	memset(orig, 0, 512);
	if (cmd(fd, 17, lba, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, orig,
		"read orig", NULL) < 0)
		return -1;
	printf("  orig: ");
	for (i = 0; i < 16; i++) printf("%02x", orig[i]);
	printf("\n");
	for (i = 0; i < 512; i++)
		pat[i] = (u8)(orig[i] ^ 0xa5);
	if (do_wr(fd, lba, pat, "write pattern") < 0)
		return -1;
	memset(buf, 0, 512);
	if (cmd(fd, 17, lba, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, buf,
		"read back", NULL) < 0)
		return -1;
	for (i = 0; i < 512; i++)
		if (buf[i] != pat[i]) break;
	ok = (i == 512);
	printf("  readback: ");
	for (i = 0; i < 16; i++) printf("%02x", buf[i]);
	printf("\n  => %s\n", ok ? "WRITE LANDED (group unprotected)"
				  : "WRITE DISCARDED (still protected)");
	if (ok) {
		if (do_wr(fd, lba, orig, "restore original") < 0)
			return -1;
		memset(buf, 0, 512);
		cmd(fd, 17, lba, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, buf,
		    "verify restore", NULL);
	}
	return ok;
}

static int do_flagread(int fd)
{
	u32 v;
	memset(buf, 0, 512);
	if (cmd(fd, 17, FLAG_LBA, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, buf,
		"read security[0]", NULL) < 0)
		return -1;
	v = buf[0] | (buf[1] << 8) | (buf[2] << 16) | ((u32)buf[3] << 24);
	printf("  security_level = %u (%s)   unlock=0x%02x%02x%02x%02x "
	       "jtag_dis=%02x%02x%02x%02x\n", v, v > 1 ? "S-ON" : "S-OFF",
	       buf[7], buf[6], buf[5], buf[4], buf[11], buf[10], buf[9], buf[8]);
	return (int)v;
}

/* CMD6 SWITCH on one EXT_CSD byte.  hboot (LK) writes cmd_set=0, mainline
 * Linux writes cmd_set=1; try 1 and fall back to 0 on SWITCH_ERROR. */
static void do_switch(int fd, u32 access, u32 index, u32 value, const char *what)
{
	u32 r1 = 0, arg;
	int cs;

	for (cs = 1; cs >= 0; cs--) {
		arg = (access << 24) | (index << 16) | (value << 8) | (u32)cs;
		if (cmd(fd, 6, arg, 0, MMC_RSP_R1B, 0, 0, NULL, what, &r1) < 0)
			return;
		wait_tran(fd);
		if (!(r1 & (1u << 7)))
			return;
		printf("  SWITCH_ERROR with cmd_set=%d, retrying\n", cs);
	}
}

/* one-shot: read state, clear the group, verify, and report */
static int do_unprotect(int fd, u32 lba)
{
	u8 e[512];
	u32 gs, grp;
	int r;

	if (read_extcsd(fd, e) < 0)
		return -1;
	gs = wp_group_size(e);
	grp = lba / gs * gs;
	print_userwp(e[EXT_CSD_USER_WP]);
	printf("group size %u sectors; target group starts at lba %u\n", gs, grp);
	do_type(fd, grp, 4);
	printf("-- write test at scratch lba %u --\n", SCRATCH_LBA);
	r = do_wtest(fd, SCRATCH_LBA);
	if (r == 1) {
		printf("=> already writable\n");
		return 0;
	}
	printf("-- CMD29 CLEAR_WRITE_PROT @ %u --\n", grp);
	cmd(fd, 29, grp, 0, MMC_RSP_R1B, 0, 0, NULL, "clr", NULL);
	wait_tran(fd);
	do_type(fd, grp, 4);
	r = do_wtest(fd, SCRATCH_LBA);
	if (r == 1) {
		printf("=> CMD29 cleared the protection\n");
		return 0;
	}
	if (e[EXT_CSD_USER_WP] & (US_PWR_WP_EN | US_PERM_WP_EN)) {
		printf("-- clearing USER_WP enable bits (CMD6 clear-bits 0x03) --\n");
		do_switch(fd, 2, EXT_CSD_USER_WP, US_PWR_WP_EN | US_PERM_WP_EN,
			  "clr USER_WP en");
		do_info(fd);
		printf("-- CMD29 again @ %u --\n", grp);
		cmd(fd, 29, grp, 0, MMC_RSP_R1B, 0, 0, NULL, "clr", NULL);
		wait_tran(fd);
		do_type(fd, grp, 4);
		r = do_wtest(fd, SCRATCH_LBA);
		if (r == 1) {
			printf("=> cleared after USER_WP clear\n");
			return 0;
		}
	}
	printf("-- CMD29 at the raw flag lba %u --\n", FLAG_LBA);
	cmd(fd, 29, FLAG_LBA, 0, MMC_RSP_R1B, 0, 0, NULL, "clr raw", NULL);
	wait_tran(fd);
	r = do_wtest(fd, SCRATCH_LBA);
	printf("=> %s\n", r == 1 ? "cleared" : "STILL PROTECTED");
	return 0;
}

static int do_flagsoff(int fd)
{
	u8 orig[512];
	int f, i;

	memset(orig, 0, 512);
	if (cmd(fd, 17, FLAG_LBA, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, orig,
		"backup security[0]", NULL) < 0)
		return -1;
	f = open("/data/local/tmp/security_lba_backup.bin", 0x241, 0644);
	if (f >= 0) { write(f, orig, 512); close(f);
		printf("  backup -> /data/local/tmp/security_lba_backup.bin\n"); }
	if (orig[0] <= 1) {
		printf("  already S-OFF (flag=%u) - nothing to do\n", orig[0]);
		return 0;
	}
	orig[0] = 0; orig[1] = 0; orig[2] = 0; orig[3] = 0;
	if (do_wr(fd, FLAG_LBA, orig, "write S-OFF flag") < 0)
		return -1;
	memset(buf, 0, 512);
	cmd(fd, 17, FLAG_LBA, 0, MMC_RSP_R1 | MMC_CMD_ADTC, 512, 1, buf,
	    "read back", NULL);
	for (i = 1; i < 512; i++) {
		if (buf[i] != orig[i]) {
			printf("  MISMATCH at byte %d (wrote %02x read %02x)\n",
			       i, orig[i], buf[i]);
			return -1;
		}
	}
	printf("  flag now = %u  => %s\n", buf[0],
	       buf[0] > 1 ? "S-ON (write did not take)" : "S-OFF");
	return 0;
}

static int do_seq(int fd)
{
	u8 e[512];
	u32 gs, flaggrp;
	int r;

	printf("== 1. card state ==\n");
	if (do_info(fd) < 0)
		return -1;
	if (read_extcsd(fd, e) < 0)
		return -1;
	gs = wp_group_size(e);
	flaggrp = FLAG_LBA / gs * gs;
	printf("== 2. WP type around the flag (group %u, lba %u) ==\n",
	       FLAG_LBA / gs, flaggrp);
	do_type(fd, flaggrp, 8);
	printf("== 3. current flag ==\n");
	do_flagread(fd);
	printf("== 4. is the flag group actually write-protected? ==\n");
	r = do_wtest(fd, SCRATCH_LBA);
	printf("   write test (scratch lba %u) => %s\n", SCRATCH_LBA,
	       r == 1 ? "WRITABLE" : r == 0 ? "PROTECTED" : "error");
	if (r == 1) {
		printf("== group already writable: writing S-OFF flag ==\n");
		do_flagsoff(fd);
		return 0;
	}
	printf("== 5. CLEAR_WRITE_PROT (CMD29) on group %u ==\n", flaggrp);
	cmd(fd, 29, flaggrp, 0, MMC_RSP_R1B, 0, 0, NULL, "clr", NULL);
	wait_tran(fd);
	printf("== 6. re-check type ==\n");
	do_type(fd, flaggrp, 8);
	printf("== 7. write test again ==\n");
	r = do_wtest(fd, SCRATCH_LBA);
	printf("   => %s\n", r == 1 ? "UNPROTECTED - now write the flag"
				   : r == 0 ? "still protected" : "error");
	if (r == 1) {
		printf("== 8. writing S-OFF flag ==\n");
		do_flagsoff(fd);
		printf("== 9. re-arming CMD28 on group %u ==\n", flaggrp);
		cmd(fd, 28, flaggrp, 0, MMC_RSP_R1B, 0, 0, NULL, "set", NULL);
		wait_tran(fd);
		do_type(fd, flaggrp, 8);
	} else {
		printf("   CMD29 did not clear a temporary WP -> try\n"
		       "     emmcwp usrwp 2 0x03   (clear PWR_WP_EN|PERM_WP_EN)\n"
		       "     emmcwp clr <lba>       (then CMD29 again)\n");
	}
	return 0;
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
	__asm__ volatile("mov r0, sp\n\tb start_c\n");
}

int main(int argc, char **argv)
{
	int fd;
	const char *mode;

	if (argc < 2) {
		printf("usage: emmcwp info|type|wp|clr|set|usrwp|rd|rdf|wtest|"
		       "flagread|flagsoff|seq ...\n");
		return 2;
	}
	mode = argv[1];
	fd = open(DEV, O_RDWR);
	if (fd < 0) {
		printf("open %s failed\n", DEV);
		return 1;
	}
	if (!strcmp(mode, "info"))
		return do_info(fd) < 0;
	if (!strcmp(mode, "type"))
		return do_type(fd, (u32)parse_num(argv[2]),
			       argc > 3 ? (int)parse_num(argv[3]) : 8) < 0;
	if (!strcmp(mode, "wp"))
		return do_wp(fd, (u32)parse_num(argv[2])) < 0;
	if (!strcmp(mode, "clr")) {
		cmd(fd, 29, (u32)parse_num(argv[2]), 0, MMC_RSP_R1B, 0, 0, NULL,
		    "CLEAR_WRITE_PROT", NULL);
		wait_tran(fd);
		return 0;
	}
	if (!strcmp(mode, "set")) {
		cmd(fd, 28, (u32)parse_num(argv[2]), 0, MMC_RSP_R1B, 0, 0, NULL,
		    "SET_WRITE_PROT", NULL);
		wait_tran(fd);
		return 0;
	}
	if (!strcmp(mode, "usrwp")) {
		u32 m = (u32)parse_num(argv[2]);
		u32 v = (u32)parse_num(argv[3]);
		do_switch(fd, m, EXT_CSD_USER_WP, v, "SWITCH USER_WP");
		do_info(fd);
		return 0;
	}
	if (!strcmp(mode, "rd"))
		return do_rd(fd, (u32)parse_num(argv[2]),
			     argc > 3 ? (int)parse_num(argv[3]) : 1, NULL) < 0;
	if (!strcmp(mode, "rdf"))
		return do_rd(fd, (u32)parse_num(argv[2]),
			     (int)parse_num(argv[3]), argv[4]) < 0;
	if (!strcmp(mode, "wtest")) {
		int r = do_wtest(fd, (u32)parse_num(argv[2]));
		return r < 0;
	}
	if (!strcmp(mode, "unprotect"))
		return do_unprotect(fd, (u32)parse_num(argv[2])) < 0;
	if (!strcmp(mode, "flagread"))
		return do_flagread(fd) < 0;
	if (!strcmp(mode, "flagsoff"))
		return do_flagsoff(fd) < 0;
	if (!strcmp(mode, "seq"))
		return do_seq(fd) < 0;
	printf("unknown mode %s\n", mode);
	return 2;
}
