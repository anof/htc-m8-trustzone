#!/bin/zsh
# night_loop.sh - try every candidate programmer until one gives a live
# Firehose session, then immediately perform the S-OFF write and verify it.
cd "$(dirname "$0")"
LOGF=/tmp/night_loop.log
LOADERS=(
	edl_prep/007b80e100040000_8f522586c4464589_fhprg.bin
	edl_prep/007b80e100040000_f7b0ceb6514cd64c_fhprg_peek.bin
	edl_prep/xiaomi_mprg8974_cancro.mbn
	edl_prep/xiaomi_prog_emmc_firehose_8974_mi3.mbn
	edl_prep/MSM8974.mbn
	edl_prep/prog_emmc_firehose_8974_oppo.mbn
	edl_prep/prog_emmc_firehose_8974_zuk.mbn
	edl_prep/prog_emmc_firehose_8974_oneplusx_peek.mbn
	edl_prep/007bc0e100000000_cc3153a80293939b_fhprg_oneplusone_peek.bin
	edl_prep/007b00e100310000_cc3153a80293939b_fhprg.bin
	edl_prep/006b10e100310000_cc3153a80293939b_fhprg.bin
	edl_prep/007b40e100310000_cc3153a80293939b_fhprg.bin
	edl_prep/prog_emmc_firehose_8974.mbn
)

for loader in $LOADERS; do
	tag=$(basename "$loader")
	echo "######## $(date +%H:%M:%S) trying $tag" | tee -a "$LOGF"

	# re-root if needed, arm magics, run s1_firehose with soff action
	if ! adb shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
		echo "--- rooting" | tee -a "$LOGF"
		python3 ensure_root.py >>"$LOGF" 2>&1 || { echo "!! root failed" | tee -a "$LOGF"; continue; }
	fi
	adb push kmod/dload/dloadmod.ko /data/local/tmp/tzctl.ko >/dev/null 2>&1
	adb shell 'su -c "/data/local/tmp/insmod_raw"' >/dev/null 2>&1
	sleep 1
	adb shell 'su -c "dmesg"' | grep -q 'DLMOD: \[fe805fe0\]' || { echo "!! arm failed" | tee -a "$LOGF"; continue; }

	RUNLOG="/tmp/soff_${tag}.log"
	nohup python3 -u s1_firehose.py "$loader" soff >"$RUNLOG" 2>&1 &
	sleep 1
	adb shell 'su -c "reboot"'

	for i in {1..40}; do
		sleep 3
		grep -q -E "S-OFF FLAG WRITTEN|program was refused|firehose never accepted|never came back|could not read" "$RUNLOG" 2>/dev/null && break
	done
	cat "$RUNLOG" | tee -a "$LOGF"

	if grep -q "S-OFF FLAG WRITTEN" "$RUNLOG"; then
		echo "######## SUCCESS with $tag" | tee -a "$LOGF"
		exit 0
	fi
	echo "######## $tag did not work" | tee -a "$LOGF"
done
echo "######## all candidates exhausted" | tee -a "$LOGF"
exit 1
