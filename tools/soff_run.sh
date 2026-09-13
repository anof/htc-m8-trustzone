#!/bin/zsh
# soff_run.sh - unattended S-OFF attempt once the phone is back on USB.
#
#   1. wait for an adb device, re-root with KingRoot if needed
#   2. push emmcwp and run the non-destructive diagnosis (emmcwp seq)
#   3. if the WP group is clearable, write the S-OFF flag and re-arm the WP
#   4. verify from the bootloader (fastboot oem readsecureflag)
#
# Everything is logged to /tmp/soff_run.log.  Safe to re-run.
cd "$(dirname "$0")" || exit 1
LOG=/tmp/soff_run.log
DEV=emmcwp
TMP=/data/local/tmp

say() { print -r -- "$@" | tee -a "$LOG" }
sh_() { adb shell "su -c '$1'" 2>&1 | tr -d '\r'; }

wait_adb() {
	local n=${1:-60} i
	for i in $(seq 1 $n); do
		if adb devices 2>/dev/null | grep -q "device$"; then return 0; fi
		sleep 5
	done
	return 1
}

say "=== soff_run $(date '+%F %T') ==="
if ! wait_adb 60; then
	say "no adb device (plug the phone in, unlocked, Android running)"
	exit 1
fi

# root: try su first, otherwise drive the KingRoot UI
if ! sh_ "id" | grep -q "uid=0"; then
	say "no root yet - running ensure_root.py"
	python3 ensure_root.py 2>&1 | tee -a "$LOG"
fi
if ! sh_ "id" | grep -q "uid=0"; then
	say "FAILED: could not obtain root"
	exit 1
fi
say "root ok: $(sh_ 'id')"

adb push "$DEV" "$TMP/$DEV" >>"$LOG" 2>&1
sh_ "chmod 755 $TMP/$DEV" >>"$LOG" 2>&1

say "--- current flag ---"
sh_ "$TMP/$DEV flagread" | tee -a "$LOG"

say "--- seq (info / WP type / write test / unprotect / flag write) ---"
sh_ "$TMP/$DEV seq" | tee -a "$LOG"

FLAG=$(sh_ "$TMP/$DEV flagread" | grep -o "security_level = [0-9]*" | awk '{print $3}')
say "--- flag after seq: ${FLAG:-unknown} ---"

if [ "${FLAG:-9}" -gt 1 ]; then
	say "--- seq did not clear it; trying the USER_WP route ---"
	sh_ "$TMP/$DEV unprotect 2148" | tee -a "$LOG"
	if sh_ "$TMP/$DEV wtest 4130" | tee -a "$LOG" | grep -q "WRITE LANDED"; then
		say "--- writing flag ---"
		sh_ "$TMP/$DEV flagsoff" | tee -a "$LOG"
		sh_ "$TMP/$DEV set 0" | tee -a "$LOG"   # re-arm group 0
	fi
	FLAG=$(sh_ "$TMP/$DEV flagread" | grep -o "security_level = [0-9]*" | awk '{print $3}')
fi

if [ "${FLAG:-9}" -le 1 ]; then
	say "*** S-OFF flag written (security_level=$FLAG) ***"
	say "verifying from the bootloader..."
	adb reboot bootloader >>"$LOG" 2>&1
	sleep 12
	fastboot oem readsecureflag 2>&1 | tee -a "$LOG"
	fastboot getvar all 2>&1 | grep -i -E "security|unlocked|cid|mid" | tee -a "$LOG"
	say "done - if it says secure_flag: 0 the device is S-OFF."
else
	say "*** not S-OFF yet (flag=$FLAG) - the group did not clear."
	say "    paste this log and we pick the next route."
fi
