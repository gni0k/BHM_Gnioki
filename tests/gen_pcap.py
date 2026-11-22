#!/usr/bin/env python3
"""
Generates synthetic capture files with known content for testing pcapreport.
Only the Python standard library is used (no scapy needed).

  python3 tests/gen_pcap.py OUTDIR

Produces:
  sample.pcap          Ethernet, microsecond, little endian - all scenarios below
  sample_be_ns.pcapng  same traffic as pcapng, big endian, nanosecond resolution
  sll_ipv6.pcap        Linux cooked (SLL) capture with IPv6 + IPv4 traffic
  truncated.pcap       sample.pcap cut in the middle of a record
  corrupt.pcap         valid header followed by an absurd record length
  garbage.bin          random bytes (not a capture file)
  empty.pcap           zero-length file

Scenarios in sample.pcap (expected findings in brackets):
  - normal HTTPS/HTTP/SSH sessions with handshake, data, FIN
  - one lossy bulk transfer with ~8% retransmissions      [High/Medium retransmission]
  - a session with zero-window stalls                      [Zero window]
  - DNS queries/answers
  - SYN port scan 10.0.0.66 -> 10.0.0.20, ports 1-300       [Port scan]
  - SMB sweep 10.0.0.66 -> 10.0.1.1-60:445                  [Network sweep]
  - spoofed SYN flood -> 10.0.0.30:80                       [SYN flood]
  - NULL / XMAS / SYN+FIN probes                            [Invalid TCP flags]
  - beacon 10.0.0.15 -> 203.0.113.50:8443 every 30 s        [Beaconing]
  - DNS amplification toward 10.0.0.40                      [UDP amplification]
  - two malformed IPv4 packets, one LAND packet, ARP, ICMP
"""
import os
import random
import struct
import sys

random.seed(20261122)
BASE_TS = 1763632800.0  # 2025-11-20 10:00:00 UTC

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(a):
    return bytes(int(x) for x in a.split("."))


def ipv4_packet(src, dst, proto, payload, ttl=64, ident=None, frag=0x4000):
    ident = random.randint(0, 65535) if ident is None else ident
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag, ttl, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr


def l4_checksum_v4(src, dst, proto, seg):
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, len(seg))
    return csum(pseudo + seg)


def tcp_seg(sport, dport, seq, ack, flags, payload=b"", win=64240):
    off = 5 << 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off, flags, win, 0, 0) + payload


def udp_seg(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


FIN, SYN, RST, PSH, ACK, URG = 1, 2, 4, 8, 16, 32


class Capture:
    def __init__(self):
        self.pkts = []  # (ts, ip_packet_bytes, ethertype)

    def add_ip(self, ts, pkt, ethertype=0x0800):
        self.pkts.append((ts, pkt, ethertype))

    def tcp(self, ts, src, dst, sport, dport, seq, ack, flags, payload=b"", win=64240):
        seg = tcp_seg(sport, dport, seq, ack, flags, payload, win)
        c = l4_checksum_v4(src, dst, 6, seg)
        seg = seg[:16] + struct.pack("!H", c) + seg[18:]
        self.add_ip(ts, ipv4_packet(src, dst, 6, seg) + seg)

    def udp(self, ts, src, dst, sport, dport, payload):
        seg = udp_seg(sport, dport, payload)
        c = l4_checksum_v4(src, dst, 17, seg) or 0xFFFF
        seg = seg[:6] + struct.pack("!H", c) + seg[8:]
        self.add_ip(ts, ipv4_packet(src, dst, 17, seg) + seg)

    def session(self, t, cli, srv, cport, sport, up=2000, down=60000, mss=1400, rtt=0.02,
                loss=0.0, zero_win=False):
        """Full TCP session: handshake, request, response stream, FIN close."""
        cs, ss = random.randint(0, 2**32 - 1), random.randint(0, 2**32 - 1)
        self.tcp(t, cli, srv, cport, sport, cs, 0, SYN)
        self.tcp(t + rtt / 2, srv, cli, sport, cport, ss, cs + 1, SYN | ACK)
        t += rtt
        self.tcp(t, cli, srv, cport, sport, cs + 1, ss + 1, ACK)
        cs += 1
        ss += 1
        sent = 0
        while sent < up:
            n = min(mss, up - sent)
            self.tcp(t, cli, srv, cport, sport, cs, ss, PSH | ACK, os.urandom(n))
            cs += n
            sent += n
            t += 0.0005
        t += rtt / 2
        sent = 0
        k = 0
        while sent < down:
            n = min(mss, down - sent)
            data = os.urandom(n)
            self.tcp(t, srv, cli, sport, cport, ss, cs, ACK, data)
            if loss and random.random() < loss:  # retransmit same segment later
                self.tcp(t + rtt * 2, srv, cli, sport, cport, ss, cs, ACK, data)
            ss += n
            sent += n
            k += 1
            if k % 2 == 0:
                w = 0 if (zero_win and k in (20, 22, 24)) else 64240
                self.tcp(t + rtt / 2, cli, srv, cport, sport, cs, ss, ACK, win=w)
            t += 0.0008
        self.tcp(t, cli, srv, cport, sport, cs, ss, FIN | ACK)
        self.tcp(t + rtt / 2, srv, cli, sport, cport, ss, cs + 1, FIN | ACK)
        self.tcp(t + rtt, cli, srv, cport, sport, cs + 1, ss + 1, ACK)
        return t + rtt


def build_sample():
    cap = Capture()
    t = BASE_TS
    eph = iter(range(40000, 65000))
    # normal sessions spread over 6 minutes
    servers = [("93.184.216.34", 443), ("151.101.1.69", 443), ("10.0.0.5", 22), ("192.0.2.80", 80)]
    for i in range(40):
        srv, port = random.choice(servers)
        cap.session(t + i * 9 + random.random(), "10.0.0.10", srv, next(eph), port,
                    up=random.randint(300, 3000), down=random.randint(2000, 80000))
    # lossy bulk transfer
    cap.session(t + 60, "10.0.0.11", "198.18.0.10", next(eph), 443, up=800, down=1500000, loss=0.08, rtt=0.06)
    # zero window stall
    cap.session(t + 120, "10.0.0.12", "10.0.0.5", next(eph), 2049, up=500, down=60000, zero_win=True)
    # DNS
    for i in range(60):
        ts = t + i * 5.5 + random.uniform(0, 4)  # irregular, like real lookups
        sp = next(eph)
        q = os.urandom(30)
        cap.udp(ts, "10.0.0.10", "10.0.0.1", sp, 53, q)
        cap.udp(ts + 0.004, "10.0.0.1", "10.0.0.10", 53, sp, os.urandom(90))
    # vertical SYN scan
    ts = t + 150
    for port in range(1, 301):
        sp = 61000 + (port % 3)
        seq = random.randint(0, 2**32 - 1)
        cap.tcp(ts, "10.0.0.66", "10.0.0.20", sp, port, seq, 0, SYN, win=1024)
        if port in (22, 80, 443):
            cap.tcp(ts + 0.0003, "10.0.0.20", "10.0.0.66", port, sp, 1000, seq + 1, SYN | ACK)
            cap.tcp(ts + 0.0005, "10.0.0.66", "10.0.0.20", sp, port, seq + 1, 0, RST, win=0)
        else:
            cap.tcp(ts + 0.0003, "10.0.0.20", "10.0.0.66", port, sp, 0, seq + 1, RST | ACK, win=0)
        ts += 0.002
    # stealth probes
    for i, fl in enumerate([0, FIN | PSH | URG, SYN | FIN, 0, FIN | PSH | URG, FIN]):
        cap.tcp(ts + i * 0.01, "10.0.0.66", "10.0.0.20", 62000 + i, 1000 + i, 1, 0, fl, win=1024)
    # horizontal sweep on 445
    ts = t + 170
    for h in range(1, 61):
        cap.tcp(ts + h * 0.01, "10.0.0.66", "10.0.1.%d" % h, 63000 + h, 445, random.randint(0, 2**32 - 1), 0, SYN, win=1024)
    # spoofed SYN flood
    ts = t + 200
    for i in range(500):
        src = "198.51.100.%d" % random.randint(1, 254)
        sp = random.randint(1024, 65535)
        seq = random.randint(0, 2**32 - 1)
        cap.tcp(ts, src, "10.0.0.30", sp, 80, seq, 0, SYN)
        cap.tcp(ts + 0.0002, "10.0.0.30", src, 80, sp, 5000 + i, seq + 1, SYN | ACK)
        ts += 0.004
    # beaconing every 30 s
    for i in range(12):
        cap.session(t + 5 + i * 30 + random.uniform(-0.3, 0.3), "10.0.0.15", "203.0.113.50", next(eph), 8443,
                    up=300, down=600)
    # DNS amplification (spoofed requests from victim address)
    ts = t + 240
    for i in range(3):
        cap.udp(ts + i, "10.0.0.40", "192.0.2.53", 33333, 53, os.urandom(40))
    for i in range(150):
        cap.udp(ts + 0.01 + i * 0.02, "192.0.2.53", "10.0.0.40", 53, 33333, os.urandom(1400))
    # LAND packet
    cap.tcp(t + 260, "10.0.0.20", "10.0.0.20", 139, 139, 1, 0, SYN)
    # ICMP echo
    for i in range(10):
        body = struct.pack("!BBHHH", 8, 0, 0, 1, i) + b"x" * 56
        body = body[:2] + struct.pack("!H", csum(body)) + body[4:]
        cap.add_ip(t + 30 + i, ipv4_packet("10.0.0.10", "8.8.8.8", 1, body) + body)
    # malformed: total length larger than frame, TCP data offset 3
    bad = bytearray(ipv4_packet("10.0.0.99", "10.0.0.20", 6, b"\0" * 20) + b"\0" * 20)
    bad[2:4] = struct.pack("!H", 400)
    bad[10:12] = b"\0\0"
    bad[10:12] = struct.pack("!H", csum(bytes(bad[:20])))
    cap.add_ip(t + 270, bytes(bad))
    seg = bytearray(tcp_seg(1234, 80, 1, 0, SYN))
    seg[12] = 3 << 4
    cap.add_ip(t + 271, ipv4_packet("10.0.0.99", "10.0.0.20", 6, bytes(seg)) + bytes(seg))
    # ARP
    for i in range(5):
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, MAC_A, ip4("10.0.0.10"), b"\0" * 6, ip4("10.0.0.%d" % (i + 1)))
        cap.add_ip(t + i * 50, arp, ethertype=0x0806)
    cap.pkts.sort(key=lambda p: p[0])
    return cap


def eth_frame(pkt, ethertype):
    f = MAC_B + MAC_A + struct.pack("!H", ethertype) + pkt
    if len(f) < 60:
        f += b"\0" * (60 - len(f))  # Ethernet padding
    return f


def write_pcap(path, frames, linktype=1, endian="<", nsec=False, snaplen=262144):
    magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))
        for ts, data in frames:
            sec = int(ts)
            frac = int(round((ts - sec) * (1e9 if nsec else 1e6)))
            if frac >= (1e9 if nsec else 1e6):
                sec, frac = sec + 1, 0
            cap = data[:snaplen]
            f.write(struct.pack(endian + "IIII", sec, frac, len(cap), len(data)))
            f.write(cap)


def write_pcapng(path, frames, linktype=1, endian=">"):
    def block(btype, body):
        body += b"\0" * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack(endian + "II", btype, ln) + body + struct.pack(endian + "I", ln)

    with open(path, "wb") as f:
        shb = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        f.write(block(0x0A0D0D0A, shb))
        opts = struct.pack(endian + "HH", 9, 1) + b"\x09\0\0\0" + struct.pack(endian + "HH", 0, 0)
        f.write(block(1, struct.pack(endian + "HHI", linktype, 0, 0) + opts))
        for ts, data in frames:
            ns = int(round(ts * 1e9))
            body = struct.pack(endian + "IIIII", 0, ns >> 32, ns & 0xFFFFFFFF, len(data), len(data)) + data
            f.write(block(6, body))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "tests/data"
    os.makedirs(out, exist_ok=True)
    cap = build_sample()
    frames = [(ts, eth_frame(p, et)) for ts, p, et in cap.pkts]
    write_pcap(os.path.join(out, "sample.pcap"), frames)
    write_pcapng(os.path.join(out, "sample_be_ns.pcapng"), frames)

    # Linux cooked capture with IPv6 TCP + IPv4 UDP
    sll = []
    t = BASE_TS + 400
    s6 = bytes.fromhex("20010db8000000000000000000000001")
    d6 = bytes.fromhex("20010db8000000000000000000000002")
    for i in range(50):
        seg = tcp_seg(50000, 443, 1000 + i * 100, 1, ACK | PSH, b"a" * 100)
        pseudo = s6 + d6 + struct.pack("!IxxxB", len(seg), 6)
        c = csum(pseudo + seg)
        seg = seg[:16] + struct.pack("!H", c) + seg[18:]
        ip6 = struct.pack("!IHBB16s16s", 0x60000000, len(seg), 6, 64, s6, d6) + seg
        sll.append((t + i * 0.1, struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\0\0", 0x86DD) + ip6))
    c2 = Capture()
    for i in range(20):
        c2.udp(t + i * 0.2, "10.1.0.1", "10.1.0.2", 5000, 5001, b"u" * 64)
    for ts, p, _ in c2.pkts:
        sll.append((ts, struct.pack("!HHH8sH", 0, 1, 6, MAC_A + b"\0\0", 0x0800) + p))
    sll.sort(key=lambda x: x[0])
    write_pcap(os.path.join(out, "sll_ipv6.pcap"), sll, linktype=113)

    raw = open(os.path.join(out, "sample.pcap"), "rb").read()
    open(os.path.join(out, "truncated.pcap"), "wb").write(raw[: len(raw) // 2 + 7])
    open(os.path.join(out, "corrupt.pcap"), "wb").write(raw[:24 + 16 + 60] + struct.pack("<IIII", 1, 0, 0xFFFFFFF0, 60))
    open(os.path.join(out, "garbage.bin"), "wb").write(bytes(random.getrandbits(8) for _ in range(4096)))
    open(os.path.join(out, "empty.pcap"), "wb").close()
    print("wrote %d frames to %s" % (len(frames), out))


if __name__ == "__main__":
    main()
