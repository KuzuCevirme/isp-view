"""ISP View - shows what your internet provider can see about your traffic.

Run:  pythonw ispview.py   (asks for admin rights; raw packet capture needs them)
"""
import ctypes
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "1.0.0"
DONATE_URL = "https://buymeacoffee.com/kuzucevirme"

FROZEN = getattr(sys, "frozen", False)  # running as a PyInstaller .exe
# BASE: where config.json lives (next to the .exe or the script).
# RES: where bundled files (web/) live.
BASE = os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__))
RES = getattr(sys, "_MEIPASS", BASE)
CONFIG_PATH = os.path.join(BASE, "config.json")


def message_box(text, title="ISP View", error=True):
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, 0x10 if error else 0x40)
    except (AttributeError, OSError):
        print(f"{title}: {text}", file=sys.stderr)

DEFAULTS = {
    "host": "127.0.0.1",
    "port": 8790,
    "open_browser_on_start": True,
    "capture_interfaces": [],
    "capture_ipv6": True,
    "max_events": 2000,
    "reverse_dns": True,
    "public_ip_lookup": True,
    "public_ip_url": "https://ipinfo.io/json",
    "ui_refresh_seconds": 2,
    "vpn_adapter_pattern": "wireguard|wintun|tap-|tun|openvpn|vpn|pia|nord|proton|mullvad|express|surfshark|tailscale|zerotier|hamachi|fortinet|cisco anyconnect|wan miniport",
}


def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg.update(json.load(f))
        except (OSError, ValueError):
            pass
    else:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULTS, f, indent=2)
    return cfg


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin():
    exe = sys.executable
    if FROZEN:
        argv = sys.argv[1:]
    else:
        pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(pyw):
            exe = pyw
        argv = [os.path.abspath(__file__)] + sys.argv[1:]
    args = " ".join(f'"{a}"' for a in argv)
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, BASE, 0)
    return r > 32


def powershell_json(script):
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                              script + " | ConvertTo-Json -Depth 5 -Compress"],
                             capture_output=True, text=True, timeout=30,
                             creationflags=0x08000000).stdout.strip()
        if not out:
            return []
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def discover_network(cfg):
    ifaces = powershell_json(r"""
Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | ForEach-Object {
  $i = $_.InterfaceIndex
  [pscustomobject]@{
    alias = $_.InterfaceAlias
    desc  = $_.InterfaceDescription
    index = $i
    v4    = @($_.IPv4Address | ForEach-Object { $_.IPAddress })
    v6    = @(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv6 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.AddressState -eq 'Preferred' } |
              Sort-Object { $_.SuffixOrigin -ne 'Random' } | ForEach-Object { $_.IPAddress })
    all   = @(Get-NetIPAddress -InterfaceIndex $i -ErrorAction SilentlyContinue | ForEach-Object { ($_.IPAddress -split '%')[0] })
    gw4   = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
    gw6   = @($_.IPv6DefaultGateway | ForEach-Object { $_.NextHop })
    dns   = @($_.DNSServer | ForEach-Object { $_.ServerAddresses })
    metric = (Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
  }
}""")
    doh = powershell_json("Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | "
                          "Select-Object ServerAddress, DohTemplate, AutoUpgrade")
    vpn_re = re.compile(cfg["vpn_adapter_pattern"], re.I)
    for i in ifaces:
        for k in ("v4", "v6", "all", "gw4", "gw6", "dns"):
            v = i.get(k) or []
            i[k] = [x for x in (v if isinstance(v, list) else [v]) if x]
        i["vpn"] = bool(vpn_re.search(f"{i.get('alias', '')} {i.get('desc', '')}"))
    wanted = cfg.get("capture_interfaces") or []
    if wanted:
        chosen = [i for i in ifaces if i["alias"] in wanted or set(i["v4"] + i["v6"]) & set(wanted)]
    else:
        # The ISP sees the physical adapter (not the inside of a VPN tunnel).
        gw = [i for i in ifaces if (i["gw4"] or i["gw6"]) and i["v4"]]
        phys = [i for i in gw if not i["vpn"]] or gw
        phys.sort(key=lambda i: i.get("metric") or 9999)
        chosen = phys[:1]
    vpns = [i for i in ifaces if i["vpn"]]
    doh_servers = {d.get("ServerAddress") for d in doh if d.get("ServerAddress")}
    for i in chosen:
        i["dns_doh"] = [s for s in i["dns"] if s in doh_servers]
    return {"interfaces": chosen, "all": ifaces, "vpn_adapters": vpns, "doh_registered": doh}


class App:
    def __init__(self):
        self.cfg = load_config()
        import capture
        self.mon = capture.Monitor(self.cfg)
        self.kind_info = capture.KIND_INFO
        self.net = {}
        self.public = None
        self.public_err = None
        self.server = None
        self.icon = None

    def lookup_public(self):
        if not self.cfg.get("public_ip_lookup", True):
            return
        try:
            req = urllib.request.Request(self.cfg["public_ip_url"],
                                         headers={"User-Agent": "isp-view", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as r:
                self.public = json.loads(r.read().decode("utf-8", "replace"))
            self.public_err = None
        except Exception as e:  # noqa: BLE001 - shown in the UI
            self.public_err = str(e)

    def refresh_network(self):
        self.net = discover_network(self.cfg)
        self.mon.set_local_ips(self.net.get("interfaces", []))
        threading.Thread(target=self.lookup_public, daemon=True).start()

    def network_watch(self):
        # IPv6 privacy addresses rotate; keep the list of "my" addresses current.
        while True:
            time.sleep(300)
            net = discover_network(self.cfg)
            if net.get("interfaces"):
                self.net = net
                self.mon.set_local_ips(net["interfaces"])

    def state(self):
        s = self.mon.snapshot()
        s["network"] = self.net
        s["public"] = self.public
        s["public_err"] = self.public_err
        s["capture_on"] = self.mon.capture_on
        s["errors"] = self.mon.errors
        s["kind_info"] = self.kind_info
        s["refresh"] = self.cfg.get("ui_refresh_seconds", 2)
        return s

    def url(self):
        return f"http://{self.cfg['host']}:{self.cfg['port']}/"

    # ---------------- web server
    def serve(self):
        app = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path in ("/", "/index.html"):
                    with open(os.path.join(RES, "web", "index.html"), "rb") as f:
                        self._send(200, f.read(), "text/html; charset=utf-8")
                elif self.path.startswith("/api/state"):
                    body = json.dumps(app.state(), default=list).encode()
                    self._send(200, body, "application/json")
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self):
                if self.path == "/api/clear":
                    app.mon.reset()
                elif self.path == "/api/pause":
                    app.mon.paused = not app.mon.paused
                elif self.path == "/api/rescan":
                    app.refresh_network()
                else:
                    return self._send(404, b"not found", "text/plain")
                self._send(200, b'{"ok":true}', "application/json")

        self.server = ThreadingHTTPServer((self.cfg["host"], int(self.cfg["port"])), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    # ---------------- tray
    def make_icon(self):
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse((2, 14, 62, 50), fill=(30, 120, 220, 255))
        d.ellipse((20, 18, 44, 46), fill=(255, 255, 255, 255))
        d.ellipse((26, 24, 38, 40), fill=(20, 20, 30, 255))
        return img

    def run_tray(self):
        import pystray

        def toggle(icon, item):
            self.mon.paused = not self.mon.paused

        def quit_(icon, item):
            icon.stop()

        menu = pystray.Menu(
            pystray.MenuItem("Open", lambda i, it: webbrowser.open(self.url()), default=True),
            pystray.MenuItem("Pause capture", toggle, checked=lambda it: self.mon.paused),
            pystray.MenuItem("Clear data", lambda i, it: self.mon.reset()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Buy me a coffee", lambda i, it: webbrowser.open(DONATE_URL)),
            pystray.MenuItem("Quit", quit_),
        )
        self.icon = pystray.Icon("isp-view", self.make_icon(), "ISP View - what your ISP sees", menu)
        self.icon.run()

    def run(self):
        self.serve()
        self.refresh_network()
        self.mon.start(self.net.get("interfaces", []))
        threading.Thread(target=self.network_watch, daemon=True).start()
        if not self.mon.capture_on:
            self.mon.errors.append("No network adapter could be captured. Set capture_interfaces in config.json.")
        if self.cfg.get("open_browser_on_start", True):
            threading.Timer(0.8, lambda: webbrowser.open(self.url())).start()
        try:
            self.run_tray()
        finally:
            self.mon.stop()
            self.server.shutdown()


def port_in_use(host, port):
    import socket
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def main():
    if "--version" in sys.argv:
        print(f"ISP View {__version__}")
        return
    if sys.platform != "win32":
        print("ISP View only runs on Windows (it uses Windows raw-socket capture).", file=sys.stderr)
        sys.exit(1)
    missing = []
    for mod, pkg in (("pystray", "pystray"), ("PIL", "pillow"), ("cryptography", "cryptography")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        message_box("Missing Python packages: " + ", ".join(missing) +
                    "\n\nInstall them with:\npip install -r requirements.txt")
        sys.exit(1)
    cfg = load_config()
    if port_in_use(cfg["host"], int(cfg["port"])):
        webbrowser.open(f"http://{cfg['host']}:{cfg['port']}/")
        return
    if not is_admin():
        if "--no-elevate" not in sys.argv and relaunch_as_admin():
            return
        message_box("ISP View needs administrator rights to read network traffic.\n\n"
                    "Right-click it and choose \"Run as administrator\".")
        sys.exit(1)
    try:
        App().run()
    except OSError as e:
        message_box(f"ISP View could not start:\n{e}\n\nIs port {cfg['port']} in use? "
                    f"Change \"port\" in config.json.")
        sys.exit(1)


if __name__ == "__main__":
    main()
