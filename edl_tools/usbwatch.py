#!/usr/bin/env python3
"""Log every USB device add/remove event on macOS while a trigger runs.

Polls ioreg fast (default 10 Hz) and prints a timestamped line whenever the
set of USB devices changes, including VID/PID/name. Meant to catch short-lived
identities like Qualcomm EDL (05c6:9008) or HTC download modes.

usage: usbwatch.py [seconds]   (default 45)
"""
import re
import subprocess
import sys
import time


def devices():
    """Return {'name vid:pid:serial': set of matching entries}."""
    try:
        out = subprocess.run(
            ["ioreg", "-p", "IOUSB", "-w0", "-l"],
            capture_output=True, text=True, timeout=5).stdout
    except Exception as exc:  # ioreg hiccup: report and keep going
        return {"error": str(exc)}
    devs = {}
    name = None
    vid = pid = serial = None

    def flush():
        if name is None:
            return
        key = "%s %s:%s %s" % (name, vid or "?", pid or "?", serial or "")
        devs[key] = key

    for line in out.splitlines():
        s = line.strip()
        m = re.match(r'^\+-o (.+?)\s*<', s)
        if m:
            flush()
            name, vid, pid, serial = m.group(1), None, None, None
            continue
        m = re.search(r'"USB Product Name" = "([^"]*)"', s)
        if m:
            name = m.group(1)
        m = re.search(r'"USB Serial Number" = "([^"]*)"', s)
        if m:
            serial = m.group(1)
        m = re.search(r'"idVendor" = (\d+|0x[0-9a-fA-F]+)', s)
        if m:
            vid = "0x%04x" % int(m.group(1), 0)
        m = re.search(r'"idProduct" = (\d+|0x[0-9a-fA-F]+)', s)
        if m:
            pid = "0x%04x" % int(m.group(1), 0)
    flush()
    return devs


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 45.0
    t0 = time.time()
    prev = {}
    print("t=+0.000  watching USB for %.0fs (10 Hz)" % secs, flush=True)
    while time.time() - t0 < secs:
        cur = devices()
        t = time.time() - t0
        for key in sorted(set(cur) | set(prev)):
            if key not in prev:
                print("t=+%.3f  ADD    %s" % (t, key), flush=True)
            elif key not in cur:
                print("t=+%.3f  REMOVE %s" % (t, key), flush=True)
        prev = cur
        time.sleep(0.1)
    print("done", flush=True)


if __name__ == "__main__":
    main()
