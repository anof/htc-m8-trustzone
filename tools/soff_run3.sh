#!/bin/zsh
# soff_run3.sh - S-OFF push, hardened.
#
#   * all tools are staged in /dev (tmpfs) so they keep working even if the
#     eMMC's block device disappears during the operation
#   * waits until the card reports TRAN (not PROG/busy) before touching it
#   * disables the card's background GC (BKOPS_EN=0) via raw CMD6
#   * remounts /data and /cache read-only (never FIFREEZE - it deadlocked)
#   * cuts the eMMC's always-on supply, detaches the stale card and lets
#     mmc_rescan re-enumerate it (mmc_rescan only re-enumerates when
#     bus_ops == NULL, which is why mmc_detect_change alone did nothing)
#   * verifies the write-protect groups are gone, writes the S-OFF flag
cd "$(dirname "$0")" || exit 1
LOG=/tmp/soff_run3.log
say() { print -r -- "$@" | tee -a "$LOG"; }

wait_adb() { local i; for i in $(seq 1 ${1:-72}); do
	adb devices 2>/dev/null | grep -q "device$" && return 0; sleep 5; done; return 1; }

say "=== soff_run3 $(date '+%F %T') ==="
wait_adb 72 || { say "no adb device"; exit 1; }
adb shell 'su -c id' 2>/dev/null | tr -d '\r' | grep -q "uid=0" || {
	say "re-rooting"; python3 ensure_root.py 2>&1 | tail -3 | tee -a "$LOG"; }
adb shell 'su -c id' 2>/dev/null | tr -d '\r' | grep -q "uid=0" || { say "no root"; exit 1; }
say "root ok"

adb push emmcwp /data/local/tmp/emmcwp >>"$LOG" 2>&1
adb push insmod_mmap /data/local/tmp/insmod_mmap >>"$LOG" 2>&1
adb push kmod/emmcpwr/emmcpwr4.ko /data/local/tmp/emmcpwr4.ko >>"$LOG" 2>&1
adb push kmod/emmcpwr/emmcpwp2.ko /data/local/tmp/emmcpwr2.ko >>"$LOG" 2>&1 2>/dev/null
adb shell 'su -c "mkdir -p /dev/soff; cp /data/local/tmp/emmcwp /data/local/tmp/insmod_mmap /dev/soff/; cp /data/local/tmp/emmcpwr4.ko /dev/soff/; chmod 755 /dev/soff/emmcwp /dev/soff/insmod_mmap; chmod 644 /dev/soff/emmcpwr4.ko; ls -l /dev/soff/"' >>"$LOG" 2>&1

say "--- wait for the card to be idle (TRAN) ---"
for i in $(seq 1 12); do
	out=$(adb shell 'su -c "/dev/soff/emmcwp stat"' 2>&1 | tr -d '\r' | tail -1)
	say "  $out"
	echo "$out" | grep -q "TRAN" && break
	sleep 5
done

say "--- disable background GC ---"
adb shell 'su -c "/dev/soff/emmcwp sw 163 0"' 2>&1 | tail -2 | tee -a "$LOG"

say "--- quiesce writes and power-cycle the eMMC ---"
adb shell 'su -c "sync; mount -o remount,ro /cache; mount -o remount,ro /data; \
	/dev/soff/insmod_mmap /dev/soff/emmcpwr4.ko; sleep 4; \
	/dev/soff/emmcwp type 0 1; /dev/soff/emmcwp wtest 4130; \
	/dev/soff/emmcwp flagsoff; /dev/soff/emmcwp flagread; \
	mount -o remount,rw /data; mount -o remount,rw /cache"' 2>&1 | tee -a "$LOG"

say "--- final flag ---"
adb shell 'su -c "/dev/soff/emmcwp flagread"' 2>&1 | tee -a "$LOG"
say "done - security_level 0 means S-OFF (confirm: adb reboot bootloader; fastboot oem readsecureflag)"
