#!/bin/zsh
# resume_soff.sh - once the phone is back on Android: for each candidate
# restart reason, log the resulting boot mode and try the S-OFF write.
cd "$(dirname "$0")"
LOGF=/tmp/resume_soff.log

wait_android() {
	local n=${1:-40}
	for i in {1..$n}; do
		adb devices | grep -q "device$" && return 0
		sleep 6
	done
	return 1
}

mode_of() {
	adb shell 'su -c "cat /proc/cmdline"' 2>/dev/null \
		| tr ' ' '\n' | grep '^androidboot.mode=' | head -1
}

try_write_flag() {
	adb shell 'su -c "/data/local/tmp/mmcrw x /dev/block/mmcblk0 0x864 1 /sdcard/sec.bin"' >/dev/null 2>&1
	adb pull /sdcard/sec.bin /tmp/sec.bin >/dev/null 2>&1
	python3 patch_sec.py >/dev/null 2>&1
	HEX=$(cat /tmp/sec_hex.txt)
	adb shell "su -c '/data/local/tmp/mmcrw w /dev/block/mmcblk0 0x864 $HEX'" >/dev/null 2>&1
	adb shell 'su -c "/data/local/tmp/mmcrw r /dev/block/mmcblk0 0x864 1"' 2>/dev/null | sed -n 2p
}

echo "=== resume $(date +%H:%M:%S)" | tee -a "$LOGF"
wait_android || { echo "no android"; exit 1; }
python3 ensure_root.py >>"$LOGF" 2>&1 || { echo "no root"; exit 1; }
adb push kmod/dload/dloadmod.ko /data/local/tmp/tzctl.ko >/dev/null 2>&1
adb shell 'su -c "/data/local/tmp/insmod_raw"' >/dev/null 2>&1

echo "baseline mode: $(mode_of)" | tee -a "$LOGF"
echo "baseline flag sector: $(try_write_flag)" | tee -a "$LOGF"

for code in 01 02 03 04 05 06 07 08 0a 0b 0c 0d 0e 0f; do
	echo "=== trying OEM reason $code" | tee -a "$LOGF"
	adb shell "su -c 'reboot oem-$code'" >/dev/null 2>&1
	sleep 10
	if ! wait_android 50; then
		echo "did not return to Android (reason $code) - needs a button press" | tee -a "$LOGF"
		exit 2
	fi
	sleep 20
	python3 ensure_root.py >>"$LOGF" 2>&1
	echo "mode: $(mode_of)" | tee -a "$LOGF"
	echo "flag sector now: $(try_write_flag)" | tee -a "$LOGF"
done
echo "done" | tee -a "$LOGF"
