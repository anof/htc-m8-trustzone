#!/usr/bin/env python3
"""ensure_root.py - get temporary root via KingRoot with no human input.

Wakes the screen, opens KingRoot, reads the UI hierarchy, taps the
"TRY TO ROOT" button whenever it appears, and waits for /system/xbin/su.
Saves a screenshot each round to /tmp/root_shots/ for later inspection.
"""
import os
import re
import subprocess
import sys
import time

SHOTS = "/tmp/root_shots"


def sh(cmd, timeout=60):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception:  # pylint: disable=broad-except
        return ""


def adb(args, timeout=60):
    return sh("adb " + args, timeout=timeout)


def root_now():
    out = adb("shell 'su -c id' 2>/dev/null", timeout=30)
    return "uid=0" in out


def wake():
    state = adb("shell dumpsys power", timeout=30)
    if "mWakefulness=Asleep" in state:
        adb("shell input keyevent 26", timeout=20)
        time.sleep(2)
    adb("shell input swipe 540 1500 540 400", timeout=20)
    time.sleep(1)


def find_root_button():
    """Return (x, y) of a clickable node whose text mentions root."""
    out = adb("shell uiautomator dump /sdcard/ui.xml", timeout=90)
    if "dumped" not in out and "UI hierchary" not in out:
        return None
    sh("adb pull /sdcard/ui.xml /tmp/ui.xml >/dev/null 2>&1", timeout=40)
    try:
        xml = open("/tmp/ui.xml").read()
    except OSError:
        return None
    for node in re.findall(r"<node[^>]*>", xml):
        m = re.search(r'text="([^"]*)"', node)
        if m is None:
            continue
        text = m.group(1).lower()
        if "root" not in text:
            continue
        if 'clickable="true"' not in node:
            continue
        b = re.search(r"bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"", node)
        if b is None:
            continue
        x1, y1, x2, y2 = (int(v) for v in b.groups())
        return ((x1 + x2) // 2, (y1 + y2) // 2)
    return None


def screenshot(tag):
    os.makedirs(SHOTS, exist_ok=True)
    adb("shell screencap -p /sdcard/kr.png", timeout=60)
    sh("adb pull /sdcard/kr.png %s/%s.png >/dev/null 2>&1" % (SHOTS, tag),
       timeout=60)


def main():
    if root_now():
        print("already root")
        return 0
    for cycle in range(1, 4):
        print("== root cycle %d" % cycle, flush=True)
        wake()
        adb("shell monkey -p com.kingroot.kinguser "
            "-c android.intent.category.LAUNCHER 1 >/dev/null 2>&1", timeout=40)
        time.sleep(8)
        for round_no in range(1, 13):
            if root_now():
                print("ROOTED", flush=True)
                return 0
            btn = find_root_button()
            screenshot("cycle%d_round%d" % (cycle, round_no))
            if btn is not None:
                print("tapping TRY TO ROOT at %d,%d" % btn, flush=True)
                adb("shell input tap %d %d" % btn, timeout=20)
                for _ in range(6):
                    time.sleep(15)
                    if root_now():
                        print("ROOTED", flush=True)
                        return 0
                continue
            time.sleep(10)
        # Not rooted this cycle: force-stop the app and try again.
        adb("shell am force-stop com.kingroot.kinguser", timeout=30)
        time.sleep(3)
    print("FAILED to obtain root", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
