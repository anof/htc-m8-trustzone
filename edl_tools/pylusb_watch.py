#!/usr/bin/env python3
"""Log VID:PID changes at 10 Hz via libusb (pyusb), the same access path the
EDL tool uses. Answers: can libusb even see the phone, and for how long?

usage: pylusb_watch.py [seconds]
"""
import sys
import time

import usb.core
import usb.backend.libusb1


def snapshot():
    be = usb.backend.libusb1.get_backend()
    out = {}
    try:
        devs = usb.core.find(find_all=True, backend=be) or []
        for d in devs:
            key = "%04x:%04x" % (d.idVendor, d.idProduct)
            out[key] = out.get(key, 0) + 1
    except Exception as exc:
        out["error:%s" % exc] = 1
    return out


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 120.0
    t0 = time.time()
    prev = {}
    while time.time() - t0 < secs:
        cur = snapshot()
        t = time.time() - t0
        for k in sorted(set(cur) | set(prev)):
            if k not in prev:
                print("t=+%7.3f  ADD    %s" % (t, k), flush=True)
            elif k not in cur:
                print("t=+%7.3f  REMOVE %s" % (t, k), flush=True)
        prev = cur
        time.sleep(0.1)
    print("done", flush=True)


if __name__ == "__main__":
    main()
