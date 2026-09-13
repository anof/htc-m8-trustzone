#!/usr/bin/env python3
"""s1_firehose.py <loader.bin> [gpt|read <lba> <count> <out.bin>]

One process, one EDL window:
  Sahara handshake -> programmer upload -> re-open USB -> Firehose command.

The programmer re-initializes the USB controller when it starts, so between
the upload and the first Firehose command the device has to be found and
opened again, quickly, without a port reset.
"""
import os
import struct
import sys
import time

import usb.core
import usb.util
import usb.backend.libusb1

VID = 0x05C6
PIDS = (0x9008, 0x900E)

HELLO_REQ, HELLO_RSP = 0x01, 0x02
READ_DATA, END_TRANSFER = 0x03, 0x04
DONE_REQ, DONE_RSP = 0x05, 0x06
CMD_READY = 0x0B
EXEC_REQ, EXEC_RSP, EXEC_DATA = 0x0D, 0x0E, 0x0F

T0 = time.time()


def log(msg):
    print("[%7.3f] %s" % (time.time() - T0, msg), flush=True)


def find_dev(any_pid=False):
    be = usb.backend.libusb1.get_backend()
    for pid in (PIDS if not any_pid else range(0x9000, 0x9100)):
        d = usb.core.find(idVendor=VID, idProduct=pid, backend=be)
        if d is not None:
            return d, pid
    return None, None


def open_dev(dev):
    dev.set_configuration()
    cfg = dev.get_active_configuration()
    for intf in cfg:
        ei = eo = None
        for e in intf:
            if usb.util.endpoint_type(e.bmAttributes) != usb.util.ENDPOINT_TYPE_BULK:
                continue
            if usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN:
                ei = e
            else:
                eo = e
        if ei is not None and eo is not None:
            return ei, eo
    raise RuntimeError("no bulk endpoints")


def rd(dev, ep, size=0x400, timeout=5000):
    return bytes(dev.read(ep.bEndpointAddress, size, timeout=timeout))


def wr(dev, ep, data, timeout=5000):
    return dev.write(ep.bEndpointAddress, data, timeout=timeout)


def hello_rsp(mode, max_cmd_len=0):
    return struct.pack("<IIIIIIIIIIII", HELLO_RSP, 0x30, 2, 1,
                       max_cmd_len, mode, 1, 2, 3, 4, 5, 6)


def do_exec(dev, ep_in, ep_out, cmd):
    wr(dev, ep_out, struct.pack("<III", EXEC_REQ, 0xC, cmd))
    hdr = rd(dev, ep_in, 0x40)
    c, ln, _ = struct.unpack("<III", hdr[:12])
    if c != EXEC_RSP:
        log("  exec %d: got cmd 0x%x" % (cmd, c))
        return None
    dev.write(ep_out.bEndpointAddress, struct.pack("<III", EXEC_DATA, 0xC, cmd))
    data = rd(dev, ep_in, 0x200)
    log("  exec %d -> %s" % (cmd, data[:32].hex()))
    return data


def firehose(loader, action):
    log("waiting for EDL device ...")
    dev = None
    while time.time() - T0 < 300:
        dev, pid = find_dev()
        if dev is not None:
            break
        time.sleep(0.03)
    if dev is None:
        log("no device")
        return 1
    log("EDL device %04x:%04x present" % (VID, pid))
    try:
        log("  bus=%s address=%s bcdDevice=%s" % (dev.bus, dev.address, dev.bcdDevice))
    except Exception:  # pylint: disable=broad-except
        pass
    ep_in, ep_out = open_dev(dev)
    try:
        for intf in dev.get_active_configuration():
            eps = ["0x%02x" % e.bEndpointAddress for e in intf]
            log("  intf %d alt %d class 0x%02x eps %s"
                % (intf.bInterfaceNumber, intf.bAlternateSetting,
                   intf.bInterfaceClass, eps))
    except Exception:  # pylint: disable=broad-except
        pass
    hdr = rd(dev, ep_in, 0x30)
    cmd, ln = struct.unpack("<II", hdr[:8])
    if cmd != HELLO_REQ:
        log("unexpected first packet 0x%x" % cmd)
        return 1
    ver, minver, maxpkt, mode = struct.unpack("<IIII", hdr[8:24])
    log("HELLO v%d min %d max_pkt 0x%x mode %d" % (ver, minver, maxpkt, mode))

    wr(dev, ep_out, hello_rsp(3))
    p = rd(dev, ep_in, 0x40)
    log("after command-mode hello: cmd=0x%x" % struct.unpack("<I", p[:4])[0])
    if os.environ.get("EDL_PROBE") == "exec":
        for c in range(0, 16):
            try:
                wr(dev, ep_out, struct.pack("<III", EXEC_REQ, 0xC, c))
                hdr = rd(dev, ep_in, 0x40, timeout=800)
                cc, ll = struct.unpack("<II", hdr[:8])
                extra = b""
                if cc == EXEC_RSP and ll > 8:
                    try:
                        wr(dev, ep_out, struct.pack("<III", EXEC_DATA, 0xC, c))
                        extra = rd(dev, ep_in, 0x100, timeout=800)
                    except Exception:  # pylint: disable=broad-except
                        pass
                log("  exec %2d -> cmd=0x%x len=%d data=%s"
                    % (c, cc, ll, extra[:24].hex()))
            except Exception as exc:  # pylint: disable=broad-except
                log("  exec %2d -> %s" % (c, exc))
        return 0
    for c in (1, 2, 3):
        try:
            do_exec(dev, ep_in, ep_out, c)
        except Exception as exc:  # pylint: disable=broad-except
            log("  exec %d failed: %s" % (c, exc))
    # Ask the target to re-open the image-transfer state; it answers with a
    # fresh HELLO which we must answer again before it accepts any data.
    wr(dev, ep_out, struct.pack("<III", 0x0C, 0xC, 3))
    p = rd(dev, ep_in, 0x40)
    c = struct.unpack("<I", p[:4])[0]
    log("after switch-mode: cmd=0x%x" % c)
    wr(dev, ep_out, hello_rsp(0))
    log("sent image-mode hello; uploading %d bytes" % len(loader))

    chunks = 0
    total_req = 0
    padded = 0
    max_end = 0
    while True:
        p = rd(dev, ep_in, 0x40)
        c, ln = struct.unpack("<II", p[:8])
        if c == READ_DATA:
            image_id, off, dlen = struct.unpack("<III", p[8:20])
            data = loader[off:off + dlen]
            if len(data) < dlen:
                padded += dlen - len(data)
                data += b"\xff" * (dlen - len(data))
            wr(dev, ep_out, data)
            chunks += 1
            total_req += dlen
            max_end = max(max_end, off + dlen)
            if chunks <= 3 or off + dlen >= len(loader):
                log("  chunk %d: off=0x%x len=0x%x" % (chunks, off, dlen))
        elif c == END_TRANSFER:
            image_id, status = struct.unpack("<II", p[8:16])
            log("END_TRANSFER image=%d status=0x%x chunks=%d"
                % (image_id, status, chunks))
            log("  bytes requested=%d file=%d padded=%d max_end=0x%x"
                % (total_req, len(loader), padded, max_end))
            if status != 0:
                return 1
            wr(dev, ep_out, struct.pack("<II", DONE_REQ, 8))
            p = rd(dev, ep_in, 0x10)
            log("after DONE: cmd=0x%x" % struct.unpack("<I", p[:4])[0])
            break
        else:
            log("unexpected packet 0x%x" % c)
            return 1

    # Hand-over to the freshly loaded programmer. EDL_HANDOVER picks how the
    # host re-establishes contact: "same" keeps the original USB handle and
    # waits; "reopen" (default) closes it and grabs the device again.
    if os.environ.get("EDL_AFTER") == "probe":
        log("probing whether the PBL still answers Sahara ...")
        time.sleep(1)
        for _ in range(3):
            try:
                wr(dev, ep_out, struct.pack("<III", EXEC_REQ, 0xC, 1))
                rep = rd(dev, ep_in, 0x40, timeout=1500)
                log("sahara probe reply: %s" % rep[:32].hex())
                break
            except Exception as exc:  # pylint: disable=broad-except
                log("sahara probe: %s" % exc)
            time.sleep(1)
        return 0
    handover = os.environ.get("EDL_HANDOVER", "reopen")
    log("handover strategy: %s" % handover)
    probe = b"<?xml version=\"1.0\" ?><data><nop/></data>"
    fh = None
    ep_in2 = ep_out2 = None

    def probe_once(d, ei, eo):
        for ee in (eo, ei):
            try:
                d.clear_halt(ee.bEndpointAddress)
            except Exception:  # pylint: disable=broad-except
                pass
        wr(d, eo, probe)
        return rd(d, ei, 0x200, timeout=1500)

    deadline = time.time() + 16
    if handover == "reset":
        time.sleep(2)
        while time.time() < deadline:
            try:
                dev.reset()
                log("USB port reset succeeded")
                time.sleep(2)
                cand, pid = find_dev()
                if cand is not None:
                    ei, eo = open_dev(cand)
                    log("after reset: %04x:%04x bus=%s addr=%s"
                        % (VID, pid, cand.bus, cand.address))
                    try:
                        rep = probe_once(cand, ei, eo)
                        log("reset-handle probe reply: %r" % rep[:64])
                    except Exception as exc:  # pylint: disable=broad-except
                        log("reset-handle probe failed: %s" % exc)
                    fh, ep_in2, ep_out2 = cand, ei, eo
                    break
            except Exception as exc:  # pylint: disable=broad-except
                log("reset attempt: %s" % exc)
            time.sleep(1.0)
    elif handover == "same":
        time.sleep(3)
        while time.time() < deadline:
            try:
                rep = probe_once(dev, ep_in, ep_out)
                log("same-handle probe reply: %r" % rep[:64])
                fh, ep_in2, ep_out2 = dev, ep_in, ep_out
                break
            except Exception as exc:  # pylint: disable=broad-except
                log("same-handle probe: %s" % exc)
            time.sleep(0.5)
    else:
        try:
            usb.util.dispose_resources(dev)
        except Exception:  # pylint: disable=broad-except
            pass
        while time.time() < deadline:
            try:
                cand, pid = find_dev()
                if cand is not None:
                    ei, eo = open_dev(cand)
                    log("reopened %04x:%04x bcdDevice=%s bus=%s addr=%s"
                        % (VID, pid, cand.bcdDevice, cand.bus, cand.address))
                    try:
                        rep = probe_once(cand, ei, eo)
                        log("reopened probe reply: %r" % rep[:64])
                    except Exception as exc:  # pylint: disable=broad-except
                        log("reopened probe failed: %s" % exc)
                    fh, ep_in2, ep_out2 = cand, ei, eo
                    break
            except Exception as exc:  # pylint: disable=broad-except
                log("open attempt: %s" % exc)
            time.sleep(0.2)
    if fh is None:
        log("firehose device never came back")
        return 1
    ep_in, ep_out = ep_in2, ep_out2

    cfgxml = ('<?xml version="1.0" encoding="UTF-8" ?><data><configure '
              'MemoryName="eMMC" Verbose="0" AlwaysValidate="0" '
              'MaxDigestTableSizeInBytes="2048" MaxPayloadSizeToTargetInBytes="1048576" '
              'ZLPAwareHost="1" SkipStorageInit="0" SkipWrite="0"/></data>')
    for attempt in range(6):
        try:
            wr(fh, ep_out, cfgxml.encode())
            rsp = b""
            t = time.time()
            while b"<response value" not in rsp and time.time() - t < 4:
                rsp += rd(fh, ep_in, 0x400, timeout=1000)
            log("configure rsp: %s" % rsp[:200].decode("latin1", "replace"))
            if b'value="ACK"' in rsp:
                break
        except Exception as exc:  # pylint: disable=broad-except
            log("configure attempt %d: %s" % (attempt, exc))
        time.sleep(0.5)
    else:
        log("firehose never accepted configure")
        return 1

    if action[0] == "gpt":
        req = ('<?xml version="1.0" ?><data><read SECTOR_SIZE_IN_BYTES="512" '
               'num_partition_sectors="34" physical_partition_number="0" '
               'start_sector="0"/></data>')
        wr(fh, ep_out, req.encode())
        rsp = b""
        t = time.time()
        while b"<response value" not in rsp and time.time() - t < 4:
            rsp += rd(fh, ep_in, 0x400, timeout=1000)
        log("gpt rsp: %s" % rsp[:200].decode("latin1", "replace"))
        if b'value="ACK"' in rsp:
            raw = b""
            while len(raw) < 34 * 512:
                raw += rd(fh, ep_in, 512, timeout=2000)
            open("gpt_dump.bin", "wb").write(raw[:34 * 512])
            log("saved gpt_dump.bin (%d bytes)" % len(raw))
    elif action[0] == "soff":
        LBA = 2148  # pg1fs offset 0x8400, the "security" flag sector

        def fh_read(lba, sectors):
            req = ('<?xml version="1.0" ?><data><read SECTOR_SIZE_IN_BYTES="512" '
                   'num_partition_sectors="%d" physical_partition_number="0" '
                   'start_sector="%d"/></data>' % (sectors, lba))
            wr(fh, ep_out, req.encode())
            rsp = b""
            t = time.time()
            while b"<response value" not in rsp and time.time() - t < 5:
                rsp += rd(fh, ep_in, 0x400, timeout=1000)
            log("read lba %d rsp: %s" % (lba, rsp[:160].decode("latin1", "replace")))
            if b'value="ACK"' not in rsp:
                return None
            data = b""
            while len(data) < sectors * 512:
                data += rd(fh, ep_in, 512, timeout=2000)
            return data

        sec = fh_read(LBA, 1)
        if sec is None or len(sec) < 512:
            log("could not read the flag sector")
            return 1
        first = struct.unpack("<I", sec[:4])[0]
        log("LBA %d first dword = 0x%08x" % (LBA, first))
        if first <= 1:
            log("already S-OFF (flag %d)" % first)
            return 0
        patch = bytearray(sec[:512])
        patch[0:4] = struct.pack("<I", 0)
        open("soff_patch.bin", "wb").write(patch)
        req = ('<?xml version="1.0" ?><data><program SECTOR_SIZE_IN_BYTES="512" '
               'num_partition_sectors="1" physical_partition_number="0" '
               'start_sector="%d"/></data>' % LBA)
        wr(fh, ep_out, req.encode())
        rsp = b""
        t = time.time()
        while b"<response value" not in rsp and time.time() - t < 5:
            rsp += rd(fh, ep_in, 0x400, timeout=1000)
        log("program rsp: %s" % rsp[:160].decode("latin1", "replace"))
        if b'value="ACK"' not in rsp:
            log("program was refused")
            return 1
        wr(fh, ep_out, bytes(patch))
        rsp = b""
        t = time.time()
        while b"<response value" not in rsp and time.time() - t < 8:
            rsp += rd(fh, ep_in, 0x400, timeout=1500)
        log("program result: %s" % rsp[:200].decode("latin1", "replace"))
        chk = fh_read(LBA, 1)
        if chk is not None and len(chk) >= 512:
            val = struct.unpack("<I", chk[:4])[0]
            log("VERIFY: LBA %d first dword now 0x%08x" % (LBA, val))
            if val <= 1:
                log("*** S-OFF FLAG WRITTEN ***")
                return 0
        return 1
    return 0


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        LOADER = f.read()
    log("loader %s (%d bytes)" % (sys.argv[1], len(LOADER)))
    action = sys.argv[2:] or ["gpt"]
    sys.exit(firehose(LOADER, action))
