#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Silicon Laboratories Inc.
"""Record Core 7.0 HCI traffic of two BlueZ emulator controllers as a btsnoop file.

btvirt (emulator/btvirt of BlueZ; Core 7.0 emulation is on BlueZ master after
5.88) serves an emulated controller to every TCP connection.  This script starts it, connects
two controllers, and drives them as a host would through the Core 7.0
procedures the emulator supports: initialisation with the 7.0 event masks and
data length commands, an LE connection moved to the LE HDT PHY, encryption with
LE Enable Encryption v2 and a key refresh, ATT and L2CAP errors for a too short
MIC, a CIS set up with LE Set CIG Parameters v2, a BIG with LE Create BIG v2,
and a few 7.0 commands the emulator rejects.  Both controllers go into one
btsnoop file in the monitor format, with their indexes.

Usage:
    tools/btvirt_core70.py <path to btvirt> <out.snoop> [port]

The result is testdata/btvirt_core70.snoop; the timing differs between runs.
"""
import select
import socket
import struct
import subprocess
import sys
import time

BTSNOOP_UNIX_EPOCH = 0x00DCDDB30F2F8000  # microseconds from year 0 to 1970

records = []


def record(index, opcode, data):
    records.append((index, opcode, data, int(time.time() * 1e6)))


class Controller:
    """One emulated controller on a TCP connection, H4 framed."""

    def __init__(self, index, port):
        self.index = index
        self.sock = socket.create_connection(("127.0.0.1", port))
        self.buf = b""
        self.events = []
        self.addr = None

    def send(self, h4type, data):
        self.sock.sendall(bytes([h4type]) + data)
        record(self.index, {1: 2, 2: 4, 5: 18}[h4type], data)

    def feed(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise SystemExit(f"controller {self.index}: connection closed")
        self.buf += chunk
        while self.buf:
            t = self.buf[0]
            if t == 4 and len(self.buf) >= 3:
                n = 3 + self.buf[2]
            elif t in (2, 5) and len(self.buf) >= 5:
                n = 5 + (struct.unpack_from("<H", self.buf, 3)[0] & 0x3FFF)
            elif t == 3 and len(self.buf) >= 4:
                n = 4 + self.buf[3]
            else:
                return
            if len(self.buf) < n:
                return
            pkt, self.buf = self.buf[1:n], self.buf[n:]
            record(self.index, {4: 3, 2: 5, 3: 7, 5: 19}[t], pkt)
            if t == 4:
                self.events.append(pkt)


controllers = []


def pump(timeout=0.05):
    ready, _, _ = select.select([c.sock for c in controllers], [], [], timeout)
    for c in controllers:
        if c.sock in ready:
            c.feed()


def wait(c, pred, what, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        for i, e in enumerate(c.events):
            if pred(e):
                return c.events.pop(i)
        pump()
    print(f"controller {c.index}: no {what}", file=sys.stderr)
    return None


def cmd(c, opcode, params=b""):
    c.send(1, struct.pack("<HB", opcode, len(params)) + params)

    def done(e):
        if e[0] == 0x0E:
            return struct.unpack_from("<H", e, 3)[0] == opcode
        return e[0] == 0x0F and struct.unpack_from("<H", e, 4)[0] == opcode

    return wait(c, done, f"completion of 0x{opcode:04x}")


def le_sub(*subs):
    return lambda e: e[0] == 0x3E and e[2] in subs


def evt(*codes):
    return lambda e: e[0] in codes


def u24(v):
    return struct.pack("<I", v)[:3]


def acl(c, handle, cid, payload):
    l2 = struct.pack("<HH", len(payload), cid) + payload
    c.send(2, struct.pack("<HH", handle | 0x2000, len(l2)) + l2)


def drive(port):
    a = Controller(0, port)
    b = Controller(1, port)
    controllers.extend([a, b])
    for c in controllers:
        record(c.index, 0, bytes([0x00, 0x00]) + bytes(6) + b"btvirt\0\0")  # New Index
    time.sleep(0.2)
    pump()

    for c in controllers:
        cmd(c, 0x0C03)  # Reset
        cmd(c, 0x1001)  # Read Local Version Information
        cmd(c, 0x1002)  # Read Local Supported Commands
        c.addr = cmd(c, 0x1009)[6:12]  # Read BD_ADDR
        cmd(c, 0x2003)  # LE Read Local Supported Features Page 0
        cmd(c, 0x2060)  # LE Read Buffer Size v2
        cmd(c, 0x0C01, bytes([0xFF] * 8))  # Set Event Mask
        cmd(c, 0x0C63, struct.pack("<Q", 0xF << 25))  # Set Event Mask Page 2: bits 25 to 28
        cmd(c, 0x2001, bytes([0xFF] * 8))  # LE Set Event Mask
        cmd(c, 0x20A4, bytes([0xFF] * 8) + bytes([0x07]) + bytes(246))  # LE Set Event Mask v2
        cmd(c, 0x0C6D, bytes([0x01, 0x00]))  # Write LE Host Support
        cmd(c, 0x2097, struct.pack("<HB", 32, 1))  # LE Set Host Feature v2: CIS (Host Support)
        cmd(c, 0x0C34, struct.pack("<HBHHHH", 1021, 64, 16, 0, 251, 8))  # Host Buffer Size v2
        cmd(c, 0x20BC, bytes([0x01, 0x00]) + struct.pack("<H", 0x001F))  # LE Set HDT Default Parameters
        cmd(c, 0x20B0, bytes([0x05]))  # LE Read Maximum Data Length v2, LE HDT
        cmd(c, 0x20B0, bytes([0x00]))  # LE Read Maximum Data Length v2, all PHYs
        cmd(c, 0x20B2, struct.pack("<HHB", 0x0100, 0x049A, 0x01))  # LE Write Suggested Default v2
        cmd(c, 0x20B1, bytes([0x01]))  # LE Read Suggested Default Data Length v2
        cmd(c, 0x2031, bytes([0x00, 0x17, 0x17]))  # LE Set Default PHY with LE HDT

    # B advertises, A connects.
    cmd(b, 0x2006, struct.pack("<HHBBB6sBB", 0x20, 0x20, 0x00, 0x00, 0x00, bytes(6), 0x07, 0x00))
    cmd(b, 0x200A, bytes([0x01]))
    cmd(a, 0x200D, struct.pack("<HHBB6sBHHHHHH", 0x60, 0x30, 0x00, 0x00, b.addr, 0x00,
                               0x18, 0x28, 0, 0x2A, 0, 0))
    ca = wait(a, le_sub(0x01, 0x0A, 0x29), "connection")
    cb = wait(b, le_sub(0x01, 0x0A, 0x29), "connection")
    ha = struct.unpack_from("<H", ca, 4)[0]
    hb = struct.unpack_from("<H", cb, 4)[0]

    # LE HDT PHY and data length.
    cmd(a, 0x2032, struct.pack("<HBBBH", ha, 0x00, 0x10, 0x10, 0x0000))  # LE Set PHY
    wait(a, le_sub(0x0C), "PHY update")
    wait(b, le_sub(0x0C), "PHY update")
    cmd(a, 0x20AA, struct.pack("<HHHB", ha, 0x1FEF, 0x4290, 0x01))  # LE Set Data Length v2
    pump(0.3)

    # Encryption with LE Enable Encryption v2, then a key refresh with a 128-bit MIC.
    ltk = bytes(range(0x10, 0x20))
    for mic in (0x01, 0x02):
        cmd(a, 0x20AF, struct.pack("<H", ha) + bytes(10) + ltk + bytes([mic, 0x00]))
        if wait(b, le_sub(0x05), "LTK request"):
            cmd(b, 0x201A, struct.pack("<H", hb) + ltk)  # LE Long Term Key Request Reply
        wait(a, evt(0x08, 0x59, 0x5A, 0x30, 0x5B), "encryption change")
        wait(b, evt(0x08, 0x59, 0x5A, 0x30, 0x5B), "encryption change")

    # ATT and L2CAP errors for a too short MIC.
    acl(a, ha, 0x0004, bytes([0x0A, 0x03, 0x00]))  # ATT Read Request
    pump(0.2)
    acl(b, hb, 0x0004, bytes([0x01, 0x0A, 0x03, 0x00, 0x14]))  # ATT Error Response
    acl(a, ha, 0x0005, bytes([0x14, 0x01, 0x0A, 0x00]) + struct.pack("<HHHHH", 0x80, 0x40, 247, 247, 10))
    pump(0.2)
    acl(b, hb, 0x0005, bytes([0x15, 0x01, 0x0A, 0x00]) + struct.pack("<HHHHH", 0, 0, 0, 0, 0x000C))
    pump(0.3)

    # A CIS with LE Set CIG Parameters v2.
    cig = bytes([0x01]) + u24(10000) + u24(10000) + bytes([0x00, 0x00, 0x00]) + struct.pack("<HHB", 10, 10, 1)
    cis = bytes([0x00]) + struct.pack("<HH", 40, 40) + bytes([0x10, 0x10, 0x02, 0x02, 0x03, 0x03]) \
        + struct.pack("<HH", 0x001F, 0x001F) + bytes([0x01, 0x00])
    e = cmd(a, 0x20B3, cig + cis)
    cis_handle = struct.unpack_from("<H", e, 8)[0]
    cmd(a, 0x2064, bytes([0x01]) + struct.pack("<HH", cis_handle, ha))  # LE Create CIS
    req = wait(b, le_sub(0x1A), "CIS request")
    cmd(b, 0x2066, req[5:7])  # LE Accept CIS Request
    wait(a, le_sub(0x19, 0x2A, 0x3A), "CIS established")
    wait(b, le_sub(0x19, 0x2A, 0x3A), "CIS established")
    cmd(a, 0x206E, struct.pack("<HBB", cis_handle, 0x00, 0x00) + bytes([0x03, 0, 0, 0, 0]) + u24(0) + bytes([0]))
    cmd(a, 0x20AB, struct.pack("<HBB", cis_handle, 0x01, 0x00) + bytes([0x03, 0, 0, 0, 0]) + u24(0)
        + struct.pack("<HH", 20, 100) + bytes([0]))  # LE Setup ISO Data Path v2

    # A BIG with LE Create BIG v2 on a periodic advertising train.
    cmd(a, 0x2036, bytes([0x01]) + struct.pack("<H", 0x0000) + u24(0x30) + u24(0x30)
        + bytes([0x07, 0x00, 0x00]) + bytes(6) + bytes([0x00, 0x7F, 0x01, 0x00, 0x01, 0x00, 0x00]))
    cmd(a, 0x203E, bytes([0x01]) + struct.pack("<HHH", 0x50, 0x50, 0x0000))
    cmd(a, 0x2040, bytes([0x01, 0x01]))  # LE Set Periodic Advertising Enable
    cmd(a, 0x2039, bytes([0x01, 0x01, 0x01, 0x00, 0x00, 0x00]))  # LE Set Extended Advertising Enable
    big = bytes([0x00, 0x01, 0x01]) + u24(10000) + struct.pack("<HH", 40, 10) \
        + bytes([0x02, 0x10, 0x00, 0x00, 0x00]) + bytes(16) + bytes([0x03]) + struct.pack("<H", 0x001F) \
        + bytes([0x02, 0x00])
    cmd(a, 0x20B6, big)  # LE Create BIG v2
    wait(a, le_sub(0x1B, 0x3B), "BIG complete")

    # Core 7.0 commands the emulator does not support.
    cmd(a, 0x20B8)  # LE Read Encryption Key Schedule Debug Mode
    cmd(a, 0x1805)  # Read Encryption Key Debug Reporting Mode
    cmd(a, 0x20BF)  # LE Read CIS Update Capabilities
    cmd(a, 0x20C0, struct.pack("<H", 8))  # LE Set Default CIS Update Parameters

    cmd(a, 0x0406, struct.pack("<HB", ha, 0x13))  # Disconnect
    wait(a, evt(0x05), "disconnection", timeout=1)
    wait(b, evt(0x05), "disconnection", timeout=1)
    pump(0.3)


def main():
    btvirt, out = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 45550
    server = subprocess.Popen([btvirt, f"-t{port}", "-C", "7.0"], stdout=subprocess.DEVNULL)
    try:
        time.sleep(0.5)
        drive(port)
    finally:
        server.terminate()
        server.wait()
    with open(out, "wb") as f:
        f.write(b"btsnoop\0" + struct.pack(">II", 1, 2001))
        for index, opcode, data, us in records:
            hdr = struct.pack(">IIIIq", len(data), len(data), (index << 16) | opcode, 0, BTSNOOP_UNIX_EPOCH + us)
            f.write(hdr)
            f.write(data)
    print(f"{out}: {len(records)} packets")


if __name__ == "__main__":
    main()
