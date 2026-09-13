#!/bin/zsh
# try_loader.sh <loader.bin> [gpt]
# One full EDL cycle: re-root, arm the emergency-dload magics, run the
# upload+firehose script, reboot, and report what the programmer answered.
set -u
cd "$(dirname "$0")"
LOADER="$1"
TAG=$(basename "$LOADER")
LOG="/tmp/try_${TAG}.log"

echo "=== $(date +%H:%M:%S) loader: $TAG"

if ! adb shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
	echo "--- re-rooting (automated)"
	python3 ensure_root.py || { echo "!! no root"; exit 1; }
fi

adb push kmod/dload/dloadmod.ko /data/local/tmp/tzctl.ko >/dev/null || exit 1
adb shell 'su -c "/data/local/tmp/insmod_raw"' >/dev/null 2>&1
sleep 1
if ! adb shell 'su -c "dmesg"' | grep -q "DLMOD: \[fe805fe0\]"; then
	echo "!! magics not armed"
	exit 1
fi
echo "--- magics armed"

nohup python3 -u s1_firehose.py "$LOADER" gpt >"$LOG" 2>&1 &
SPID=$!
sleep 1
adb shell 'su -c "reboot"'

for i in {1..40}; do
	sleep 3
	grep -q -E "configure rsp|never accepted|never came back" "$LOG" 2>/dev/null && break
done
echo "--- result:"
tail -25 "$LOG"
