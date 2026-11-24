"""Packet capture and analysis: works out what your ISP can see.

Uses Windows raw sockets with SIO_RCVALL (needs admin, no Npcap/driver needed).
Everything is kept in memory only.
"""
import collections
import ipaddress
import socket
import struct
import threading
import time

import quic

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

DOH_HOSTS = {
    "dns.google", "dns.google.com", "cloudflare-dns.com", "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "security.cloudflare-dns.com", "family.cloudflare-dns.com", "dns.quad9.net",
    "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net", "doh.opendns.com",
    "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.adguard.com", "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com", "doh.mullvad.net", "dns.mullvad.net", "base.dns.mullvad.net",
    "doh.dns.sb", "dns.controld.com", "freedns.controld.com", "doh.libredns.gr",
    "dns.alidns.com", "doh.pub", "dns.twnic.tw", "ordns.he.net",
}
ECH_FRONTS = {"cloudflare-ech.com", "encryptedsni.com", "crypto.cloudflare.com", "public.example.com"}
VPN_PORTS = {51820: "WireGuard", 1194: "OpenVPN", 500: "IPsec/IKE", 4500: "IPsec NAT-T",
             1701: "L2TP", 1723: "PPTP", 443: None}
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")

KIND_INFO = {
    "DNS": "Plain DNS lookup. The website name is sent unencrypted.",
    "HTTP": "Unencrypted web request. The full URL is visible, and so is the page content.",
    "TLS": "HTTPS connection. The site name is visible in the handshake (SNI). The page content is encrypted.",
    "QUIC": "HTTP/3 (QUIC) connection. The site name can be decrypted from the first packet. The page content is encrypted.",
    "ECH": "Encrypted Client Hello. The real site name is hidden; only a shared front name is visible.",
    "DoH": "Encrypted DNS over HTTPS. Your DNS lookups are hidden, but the use of the DoH provider is visible.",
    "DoT": "Encrypted DNS over TLS (port 853). Your DNS lookups are hidden, but the use of DoT is visible.",
    "VPN": "VPN/tunnel traffic. Only the tunnel server and traffic volume are visible.",
}


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


# ---------------------------------------------------------------- parsers

def parse_client_hello(hs):
    """hs = handshake bytes starting with the type byte. Returns dict, 'more' or None."""
    if len(hs) < 4 or hs[0] != 1:
        return None
    hl = int.from_bytes(hs[1:4], "big")
    body = hs[4:4 + hl]
    if len(body) < hl:
        return "more"
    res = {"sni": None, "alpn": [], "ech": False}
    try:
        p = 34
        p += 1 + body[p]
        p += 2 + struct.unpack_from(">H", body, p)[0]
        p += 1 + body[p]
        if p + 2 > len(body):
            return res
        end = p + 2 + struct.unpack_from(">H", body, p)[0]
        p += 2
        while p + 4 <= end:
            et, el = struct.unpack_from(">HH", body, p)
            d = body[p + 4:p + 4 + el]
            p += 4 + el
            if et == 0 and len(d) > 5:
                nl = struct.unpack_from(">H", d, 3)[0]
                res["sni"] = d[5:5 + nl].decode("ascii", "replace").lower()
            elif et == 16 and len(d) > 2:
                q = 2
                while q < len(d):
                    ln = d[q]
                    res["alpn"].append(d[q + 1:q + 1 + ln].decode("ascii", "replace"))
                    q += 1 + ln
            elif et == 0xFE0D:
                res["ech"] = True
    except (IndexError, struct.error):
        pass
    return res


def tls_handshake_bytes(buf):
    """Concatenate handshake payload of complete TLS records. Returns (bytes, complete_records_ok)."""
    out = bytearray()
    p = 0
    while p + 5 <= len(buf):
        if buf[p] != 0x16:
            break
        ln = struct.unpack_from(">H", buf, p + 3)[0]
        if p + 5 + ln > len(buf):
            out += buf[p + 5:]
            return bytes(out), False
        out += buf[p + 5:p + 5 + ln]
        p += 5 + ln
    return bytes(out), True


def _dns_name(msg, off):
    labels = []
    jumped = False
    ret = off
    for _ in range(128):
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                ret = off + 2
            jumped = True
            off = ptr
            continue
        labels.append(msg[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    if not jumped:
        ret = off
    return ".".join(labels).lower(), ret


def parse_dns(msg):
    """Returns (is_response, qname, qtype, answers[(type, value)], rcode) or None."""
    try:
        if len(msg) < 12:
            return None
        _id, flags, qd, an = struct.unpack_from(">HHHH", msg, 0)
        if qd < 1:
            return None
        qname, p = _dns_name(msg, 12)
        qtype = struct.unpack_from(">H", msg, p)[0]
        p += 4
        for _ in range(qd - 1):
            _, p = _dns_name(msg, p)
            p += 4
        answers = []
        resp = bool(flags & 0x8000)
        if resp:
            for _ in range(min(an, 64)):
                _, p = _dns_name(msg, p)
                t, _c, _ttl, rl = struct.unpack_from(">HHIH", msg, p)
                p += 10
                rd = msg[p:p + rl]
                if t == 1 and rl == 4:
                    answers.append(("A", socket.inet_ntop(socket.AF_INET, rd)))
                elif t == 28 and rl == 16:
                    answers.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rd)))
                elif t == 5:
                    answers.append(("CNAME", _dns_name(msg, p)[0]))
                p += rl
        return resp, qname, QTYPES.get(qtype, str(qtype)), answers, flags & 0xF
    except (IndexError, struct.error):
        return None


# ---------------------------------------------------------------- monitor

class Monitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.RLock()
        self.paused = False
        self.errors = []
        self.sockets = []
        self.local_ips = set()
        self.capture_on = []  # [(alias, ip)]
        self.reset()

    # ---- state
    def reset(self):
        with getattr(self, "lock", threading.RLock()):
            self.started = time.time()
            self.events = collections.deque(maxlen=int(self.cfg.get("max_events", 2000)))
            self.event_id = 0
            self.recent = {}
            self.domains = {}
            self.hosts = {}
            self.ip_names = {}
            self.counts = collections.Counter()
            self.bytes_out = 0
            self.bytes_in = 0
            self.packets = 0
            self.tcp_buf = {}
            self.quic_buf = {}
            self.vpn_seen = set()
            self.rdns_done = {}
            self.rdns_queue = collections.deque()
            self.rdns_arpa = set()
            self.v6peers = {}
            self.v6pending = {}

    def _event(self, kind, name, detail, remote, port, now):
        key = (kind, name, remote if kind in ("DoT", "VPN") else None)
        ev = self.recent.get(key)
        if ev and now - ev["t"] < 3:
            if detail and detail not in ev["detail"]:
                ev["detail"] = (ev["detail"] + ", " + detail).strip(", ")
            ev["hits"] += 1
        else:
            self.event_id += 1
            ev = {"id": self.event_id, "t": now, "kind": kind, "name": name, "detail": detail or "",
                  "remote": remote, "port": port, "hits": 1}
            self.events.append(ev)
            self.recent[key] = ev
            if len(self.recent) > 5000:
                self.recent = {k: v for k, v in self.recent.items() if now - v["t"] < 3}
        self.counts[kind] += 1
        if name:
            d = self.domains.get(name)
            if d is None:
                d = self.domains[name] = {"name": name, "first": now, "last": now, "hits": 0,
                                          "kinds": set(), "ips": set()}
            d["last"] = now
            d["hits"] += 1
            d["kinds"].add(kind)
            if remote and kind not in ("DNS",):
                d["ips"].add(remote)
                self._name_ip(remote, name)

    def _name_ip(self, ip, name):
        s = self.ip_names.setdefault(ip, [])
        if name not in s:
            s.append(name)
            if len(s) > 8:
                s.pop(0)

    # ---- capture setup
    def start(self, interfaces):
        """interfaces: [{'alias':..., 'v4': [...], 'v6': [...], 'all': [...]}]"""
        self.set_local_ips(interfaces)
        for iface in interfaces:
            alias = iface.get("alias", "?")
            v4 = iface.get("v4", [])
            if v4:
                self._open(socket.AF_INET, v4[0], alias)
            if self.cfg.get("capture_ipv6", True) and iface.get("v6"):
                self._open(socket.AF_INET6, iface["v6"][0], alias)
        if self.cfg.get("reverse_dns", True):
            threading.Thread(target=self._rdns_worker, daemon=True).start()

    def set_local_ips(self, interfaces):
        ips = set(self.local_ips)
        for iface in interfaces:
            ips.update(iface.get("v4", []) + iface.get("v6", []) + iface.get("all", []))
        self.local_ips = ips

    def _open(self, family, ip, alias):
        try:
            if family == socket.AF_INET:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                # Windows hands IPv6 raw captures over WITHOUT the IPv6 header:
                # data starts at the TCP/UDP header and recvfrom() gives the source.
                s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, 0)
                s.bind((ip, 0, 0, 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except OSError as e:
            self.errors.append(f"Could not capture on {alias} ({ip}): {e}")
            return
        self.sockets.append(s)
        self.capture_on.append({"alias": alias, "ip": ip, "family": "IPv4" if family == socket.AF_INET else "IPv6"})
        threading.Thread(target=self._loop, args=(s, family), daemon=True).start()

    def stop(self):
        for s in self.sockets:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                s.close()
            except OSError:
                pass

    def _loop(self, s, family):
        v6 = family == socket.AF_INET6
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                return
            if self.paused or not data:
                continue
            try:
                if v6:
                    self._packet6(memoryview(data), addr[0].split("%")[0])
                else:
                    self._packet(memoryview(data))
            except Exception:  # never let one odd packet kill the capture
                pass

    # ---- packet handling
    def _packet6(self, d, src):
        n = len(d)
        if n < 8:
            return
        sport, dport, ulen = struct.unpack_from(">HHH", d, 0)
        if ulen == n:
            proto, payload = 17, d[8:]
        elif n >= 20 and 5 <= (d[12] >> 4):
            proto, payload = 6, d[(d[12] >> 4) * 4:]
        else:
            return
        total = n + 40
        now = time.time()
        if src in self.local_ips:
            key = (proto, sport, dport)
            remote = self.v6peers.get(key)
            if remote is None:
                # Destination is not in the capture; wait for the reply to learn it.
                with self.lock:
                    q = self.v6pending.setdefault(key, [])
                    if len(q) < 8:
                        q.append((bytes(d), now))
                    if len(self.v6pending) > 3000:
                        self.v6pending = {k: v for k, v in self.v6pending.items() if now - v[-1][1] < 10}
                return
            self._handle(True, remote, proto, sport, dport, payload, total, now)
        else:
            key = (proto, dport, sport)
            if self.v6peers.get(key) != src:
                if len(self.v6peers) > 50000:
                    self.v6peers.clear()
                self.v6peers[key] = src
            with self.lock:
                pend = self.v6pending.pop(key, None)
            for raw, t in pend or ():
                pl = raw[8:] if proto == 17 else raw[(raw[12] >> 4) * 4:]
                self._handle(True, src, proto, dport, sport, memoryview(pl), len(raw) + 40, t)
            self._handle(False, src, proto, sport, dport, payload, total, now)

    def _packet(self, d):
        ver = d[0] >> 4
        if ver == 4:
            ihl = (d[0] & 0x0F) * 4
            total = struct.unpack_from(">H", d, 2)[0] or len(d)
            if struct.unpack_from(">H", d, 6)[0] & 0x1FFF:
                return  # non-first fragment
            proto = d[9]
            src = socket.inet_ntop(socket.AF_INET, d[12:16])
            dst = socket.inet_ntop(socket.AF_INET, d[16:20])
            off = ihl
        elif ver == 6:
            total = struct.unpack_from(">H", d, 4)[0] + 40
            proto = d[6]
            src = socket.inet_ntop(socket.AF_INET6, d[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, d[24:40])
            off = 40
            for _ in range(6):
                if proto in (0, 43, 60):
                    proto = d[off]
                    off += (d[off + 1] + 1) * 8
                elif proto == 44:
                    proto = d[off]
                    off += 8
                else:
                    break
        else:
            return

        if src in self.local_ips:
            out, remote = True, dst
        elif dst in self.local_ips:
            out, remote = False, src
        else:
            return

        public = is_public(remote)
        sport = dport = 0
        payload = b""
        if proto == 6 and len(d) >= off + 20:
            sport, dport = struct.unpack_from(">HH", d, off)
            doff = (d[off + 12] >> 4) * 4
            payload = d[off + doff:]
        elif proto == 17 and len(d) >= off + 8:
            sport, dport = struct.unpack_from(">HH", d, off)
            payload = d[off + 8:]
        self._handle(out, remote, proto, sport, dport, payload, total, time.time())

    def _handle(self, out, remote, proto, sport, dport, payload, total, now):
        public = is_public(remote)
        rport = dport if out else sport
        lport = sport if out else dport

        with self.lock:
            # DNS to any resolver (a router forwards it upstream, usually to the ISP)
            if rport == 53 and payload:
                self._dns(payload, proto, out, remote, now)
            if not public:
                return
            self.packets += 1
            if out:
                self.bytes_out += total
            else:
                self.bytes_in += total
            h = self.hosts.get(remote)
            if h is None:
                h = self.hosts[remote] = {"ip": remote, "out": 0, "in": 0, "pkts": 0, "first": now,
                                          "last": now, "ports": set(), "proto": set()}
                if self.cfg.get("reverse_dns", True):
                    self.rdns_queue.append(remote)
            h["out" if out else "in"] += total
            h["pkts"] += 1
            h["last"] = now
            if len(h["ports"]) < 12:
                h["ports"].add(rport)
            h["proto"].add({6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 50: "ESP"}.get(proto, str(proto)))

            if proto == 50 and "esp:" + remote not in self.vpn_seen:
                self.vpn_seen.add("esp:" + remote)
                self._event("VPN", None, "IPsec ESP tunnel", remote, 0, now)
            if not out or not payload:
                return
            if proto == 6:
                self._tcp_out(payload, remote, rport, lport, now)
            elif proto == 17:
                self._udp_out(payload, remote, rport, lport, now)

    def _dns(self, payload, proto, out, remote, now):
        msg = bytes(payload)
        if proto == 6:
            if len(msg) < 14:
                return
            msg = msg[2:]
        r = parse_dns(msg)
        if not r:
            return
        resp, qname, qtype, answers, rcode = r
        if not qname:
            return
        if qname.endswith(".arpa") and qname in self.rdns_arpa:
            return  # our own reverse lookup
        if not resp and out:
            self._event("DNS", qname, qtype, remote, 53, now)
        elif resp:
            for t, v in answers:
                if t in ("A", "AAAA"):
                    self._name_ip(v, qname)
                    dm = self.domains.get(qname)
                    if dm is not None and len(dm["ips"]) < 16:
                        dm["ips"].add(v)

    def _tcp_out(self, payload, remote, rport, lport, now):
        key = (remote, rport, lport)
        if rport == 853 and ("dot:" + remote) not in self.vpn_seen:
            self.vpn_seen.add("dot:" + remote)
            self._event("DoT", None, "DNS over TLS", remote, rport, now)
        buf = self.tcp_buf.get(key)
        if buf is None:
            b0 = payload[0]
            if b0 == 0x16 and len(payload) > 5 and payload[1] == 3:
                buf = self.tcp_buf[key] = {"b": bytearray(payload), "t": now, "n": 1}
            elif bytes(payload[:8]).startswith(HTTP_METHODS):
                self._http(bytes(payload[:4096]), remote, rport, now)
                return
            else:
                return
        else:
            buf["b"] += payload
            buf["n"] += 1
        hs, _ = tls_handshake_bytes(buf["b"])
        r = parse_client_hello(hs)
        if r == "more" and buf["n"] < 12 and len(buf["b"]) < 32768:
            if len(self.tcp_buf) > 2000:
                self.tcp_buf = {k: v for k, v in self.tcp_buf.items() if now - v["t"] < 10}
            return
        self.tcp_buf.pop(key, None)
        if isinstance(r, dict):
            self._hello(r, "TLS", remote, rport, now)

    def _udp_out(self, payload, remote, rport, lport, now):
        vpn = VPN_PORTS.get(rport)
        if vpn and ("vpn:" + remote) not in self.vpn_seen:
            self.vpn_seen.add("vpn:" + remote)
            self._event("VPN", None, f"{vpn} tunnel (UDP {rport})", remote, rport, now)
        if not quic.is_long_header_initial(payload):
            return
        for dcid, pt in quic.decrypt_initials(bytes(payload)):
            key = (remote, lport, dcid)
            st = self.quic_buf.get(key)
            if st is None:
                if len(self.quic_buf) > 1000:
                    self.quic_buf = {k: v for k, v in self.quic_buf.items() if now - v["t"] < 10}
                st = self.quic_buf[key] = {"f": {}, "t": now, "done": False}
            if st["done"]:
                continue
            for o, data in quic.crypto_frames(pt):
                st["f"][o] = data
            stream = bytearray()
            for o in sorted(st["f"]):
                if o > len(stream):
                    break
                stream[o:o + len(st["f"][o])] = st["f"][o]
            r = parse_client_hello(bytes(stream))
            if isinstance(r, dict):
                st["done"] = True
                self._hello(r, "QUIC", remote, rport, now)

    def _hello(self, r, kind, remote, rport, now):
        sni = r.get("sni")
        alpn = ",".join(r.get("alpn") or [])
        if sni in DOH_HOSTS:
            self._event("DoH", sni, f"encrypted DNS via {kind}", remote, rport, now)
        elif r.get("ech") and sni in ECH_FRONTS:
            # Real ECH: the visible name is a shared front, the real one is encrypted.
            self._event("ECH", sni, f"real site name hidden ({kind})", remote, rport, now)
        elif sni:
            # Chrome adds a dummy (GREASE) ECH extension everywhere; the name is still visible.
            self._event(kind, sni, alpn, remote, rport, now)
        else:
            self._event(kind, None, "no name sent (IP only)", remote, rport, now)

    def _http(self, data, remote, rport, now):
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
        try:
            method, path, _ = head[0].split(" ", 2)
        except ValueError:
            return
        host = ""
        ua = ""
        for line in head[1:]:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k == "host":
                host = v.strip().lower()
            elif k == "user-agent":
                ua = v.strip()
        name = host.split(":")[0] if host else None
        url = path if path.startswith("http") else f"http://{host or remote}{path}"
        detail = f"{method} {url[:300]}" + (f"  |  UA: {ua[:120]}" if ua else "")
        self._event("HTTP", name, detail, remote, rport, now)

    # ---- reverse DNS (what the IP itself tells your ISP)
    def _rdns_worker(self):
        while True:
            try:
                ip = self.rdns_queue.popleft()
            except IndexError:
                time.sleep(1)
                continue
            if ip in self.rdns_done:
                continue
            try:
                self.rdns_arpa.add(ipaddress.ip_address(ip).reverse_pointer)
                name = socket.gethostbyaddr(ip)[0].lower()
            except (OSError, ValueError):
                name = None
            self.rdns_done[ip] = name

    # ---- snapshot for the UI
    def snapshot(self, max_rows=400):
        with self.lock:
            now = time.time()
            for k in [k for k, v in self.tcp_buf.items() if now - v["t"] > 15]:
                del self.tcp_buf[k]
            events = list(self.events)[-max_rows:]
            domains = sorted(self.domains.values(), key=lambda x: x["last"], reverse=True)[:max_rows * 2]
            hosts = sorted(self.hosts.values(), key=lambda x: x["out"] + x["in"], reverse=True)[:max_rows]
            dom_bytes = collections.Counter()
            for h in self.hosts.values():
                for n in self.ip_names.get(h["ip"], [])[:1]:
                    dom_bytes[n] += h["out"] + h["in"]
            return {
                "now": now,
                "started": self.started,
                "paused": self.paused,
                "packets": self.packets,
                "bytes_out": self.bytes_out,
                "bytes_in": self.bytes_in,
                "counts": dict(self.counts),
                "events": events,
                "domains": [dict(d, kinds=sorted(d["kinds"]), ips=sorted(d["ips"])[:8],
                                 bytes=dom_bytes.get(d["name"], 0)) for d in domains],
                "hosts": [dict(h, ports=sorted(h["ports"]), proto=sorted(h["proto"]),
                               names=self.ip_names.get(h["ip"], []),
                               rdns=self.rdns_done.get(h["ip"])) for h in hosts],
                "host_count": len(self.hosts),
                "domain_count": len(self.domains),
            }
