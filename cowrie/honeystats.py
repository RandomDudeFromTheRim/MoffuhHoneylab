#!/usr/bin/env python3
"""Private JSON API for an internal honeypot dashboard.

Routes expose counts and a visitor feed derived from local Cowrie and companion logs. Bind to loopback
by default and restrict any remote dashboard access at the firewall or authenticated reverse proxy.
"""
import collections, datetime as dt, importlib.util, json, os, socket, struct, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

spec = importlib.util.spec_from_file_location("digest", os.path.join(os.path.dirname(__file__), "digest.py"))
digest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(digest)

# Optional operator-defined names to omit from player counters.
MC_EXCLUDE = {"labplayerone", "labplayertwo", "labfarmer"} | {v.strip().casefold() for v in os.environ.get("HONEYPOT_EXCLUDED_MC_NAMES", "").split(",") if v.strip()}


def _rcon_password():
    return os.environ.get("MCPOT_RCON_PASSWORD") or None


def _rcon_read(s):
    raw = b""
    while len(raw) < 4:
        c = s.recv(4 - len(raw))
        if not c:
            return ""
        raw += c
    ln = struct.unpack("<i", raw)[0]
    if ln < 10 or ln > (1 << 20):
        return ""
    data = b""
    while len(data) < ln:
        c = s.recv(ln - len(data))
        if not c:
            break
        data += c
    return data[8:-2].decode(errors="replace") if len(data) >= 10 else ""


def rcon_list(host=None, port=None, timeout=3):
    """Online bait-server players via RCON `list`, excluding operator-configured decoys. None if unreachable."""
    pw = _rcon_password()
    host = host or os.environ.get("MCPOT_RCON_HOST", "127.0.0.1")
    port = port or int(os.environ.get("MCPOT_RCON_PORT", "25575"))
    if not pw:
        return None

    def pkt(rid, typ, body):
        payload = struct.pack("<ii", rid, typ) + body.encode() + b"\x00\x00"
        return struct.pack("<i", len(payload)) + payload
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(pkt(1, 3, pw))       # SERVERDATA_AUTH
            _rcon_read(s)
            s.sendall(pkt(2, 2, "list"))   # SERVERDATA_EXECCOMMAND
            resp = _rcon_read(s)
    except (OSError, struct.error):
        return None
    if ":" not in resp:               # "There are 0 ... online:" with no names
        return 0
    names = [n.strip() for n in resp.split(":", 1)[1].split(",") if n.strip()]
    return len([n for n in names if n.lower() not in MC_EXCLUDE])


CACHE_S = 30
FEED_N = 8
_cache = {}


def ago(ts):
    s = max(0, int(time.time() - ts))
    return f"{s // 60} min ago" if s < 3600 else f"{s // 3600} h ago" if s < 86400 else f"{s // 86400} d ago"


def cowrie():
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    sessions, ips, logins, cmds, downloads = 0, set(), 0, 0, 0
    for e in digest.events(since):
        ev = e.get("eventid", "")
        if ev == "cowrie.session.connect":
            sessions += 1
            ips.add(e.get("src_ip"))
        elif ev == "cowrie.login.success":
            logins += 1
        elif ev == "cowrie.command.input":
            cmds += 1
        elif ev in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            downloads += 1
    return {"sessions": sessions, "ips": len(ips), "logins": logins, "commands": cmds, "downloads": downloads}


def minecraft():
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    m = digest.minecraft(since)
    t = m["types"]
    try:
        bait = json.load(open("/var/lib/mcbait/state.json"))
    except (OSError, ValueError):
        bait = {}
    st = bait.get("stats", {})
    live = rcon_list()
    return {"pings": t["ping"] + t["legacy_ping"], "joins": t["join"], "ips": len(m["ips"]),
            "usernames": len(m["names"]), "world": bait.get("wipes", 0) + 1,
            "live": live if live is not None else 0,
            "griefers": st.get("griefers", 0), "visitors": st.get("players", 0),
            "blocks": st.get("player_blocks", 0)}


def docker():
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    d = digest.docker(since)
    return {"requests": d["events"], "ips": len(d["ips"]), "creates": len(d["creates"]),
            "escapes": len(d["escapes"]), "loot": len(d["loot"])}


def tarpit():
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    d = digest.tarpit(since)
    return {"pinned": d["conns"], "open": d["open"], "ips": len(d["ips"]),
            "wasted_h": round(d["held_s"] / 3600, 1)}


def redis():
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    d = digest.redis(since)
    return {"commands": d["cmds"], "ips": len(d["ips"]), "rce": len(d["rce_ips"]), "loot": len(d["loot"])}


def feed():
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)
    items = []
    for e in digest.events(since):
        ev, ip = e.get("eventid", ""), e.get("src_ip", "?")
        ts = dt.datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp()
        what = None
        if ev == "cowrie.login.success":
            what = f"ssh login for {e.get('username', '?')}"
        elif ev == "cowrie.command.input":
            what = "$ " + digest.clip((e.get("input") or "").strip(), 60)
        elif ev == "cowrie.session.file_download":
            what = "downloaded " + digest.clip(e.get("url") or "?", 50)
        elif ev == "cowrie.session.file_upload":
            what = f"uploaded {e.get('filename', '?')}"
        elif ev == "cowrie.session.connect":
            what = f"{e.get('protocol', 'ssh')} knock"
        if what:
            items.append((ts, ip, what))
    try:
        for line in open(digest.MC_LOG, errors="replace"):
            e = json.loads(line)
            if e.get("ts", 0) < since.timestamp() or digest.is_private(e.get("ip", "")):
                continue
            ver = digest.MC_VERSIONS.get(e.get("proto"), f"proto {e.get('proto')}") if "proto" in e else ""
            what = {"ping": f"mc ping ({ver})", "legacy_ping": "mc legacy ping",
                    "join": f"mc join as {e.get('name', '?')} ({ver})"}.get(e.get("type"))
            if what:
                items.append((e["ts"], e.get("ip", "?"), what))
    except (OSError, ValueError):
        pass
    try:
        for line in open(digest.DOCKER_LOG, errors="replace"):
            e = json.loads(line)
            ip = e.get("src_ip", "?")
            if digest.is_private(ip) or not e.get("ts"):
                continue
            ts = dt.datetime.fromisoformat(e["ts"]).timestamp()
            if ts < since.timestamp():
                continue
            path = e.get("path", "")
            if path == "/containers/create" and isinstance(e.get("body"), dict):
                cmd = e["body"].get("Cmd") or e["body"].get("Entrypoint") or []
                cmd = " ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)
                items.append((ts, ip, "docker create: " + digest.clip(cmd or str(e["body"].get("Image", "")), 50)))
            elif path.endswith("/exec"):
                items.append((ts, ip, "docker exec"))
    except (OSError, ValueError):
        pass
    # a knock followed by a login from the same IP is noise: keep the more interesting line
    items.sort(reverse=True)
    out, seen_login = [], set()
    for ts, ip, what in items:
        if what.endswith("knock") and ip in seen_login:
            continue
        if not what.endswith("knock"):
            seen_login.add(ip)
        out.append({"what": what, "who": f"{ip} · {ago(ts)}"})
        if len(out) >= FEED_N:
            break
    return {"items": out or [{"what": "nobody yet", "who": ""}]}


ROUTES = {"/cowrie": cowrie, "/minecraft": minecraft, "/docker": docker, "/tarpit": tarpit,
          "/redis": redis, "/feed": feed}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        fn = ROUTES.get(self.path.split("?")[0])
        if not fn:
            self.send_error(404)
            return
        cache_key = self.path.split("?")[0]
        hit = _cache.get(cache_key)
        if not hit or time.time() - hit[0] > CACHE_S:
            try:
                hit = (time.time(), json.dumps(fn()).encode())
            except Exception as e:  # never take the dashboard down over a bad log line
                hit = (time.time(), json.dumps({"error": type(e).__name__}).encode())
            _cache[cache_key] = hit
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(hit[1])

    def log_message(self, *a):
        pass


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, handler):
        self._slots = threading.BoundedSemaphore(16)
        super().__init__(address, handler)

    def get_request(self):
        request, client = super().get_request()
        request.settimeout(5)
        return request, client

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


if __name__ == "__main__":
    bind = os.environ.get("HONEYSTATS_BIND", "127.0.0.1")
    port = int(os.environ.get("HONEYSTATS_PORT", "18082"))
    BoundedThreadingHTTPServer((bind, port), H).serve_forever()
