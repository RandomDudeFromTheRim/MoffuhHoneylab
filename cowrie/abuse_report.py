#!/usr/bin/env python3
"""Optionally report observed honeypot source IPs to AbuseIPDB. Submission requires --submit.

Reuses digest.py's event reader, so it sees exactly the same outside visitors as the 09:00 report
(private IPs and operator-configured proxy addresses are skipped). Each IP is
reported at most once per REPORT_EVERY_H hours (state file). The comment carries no sensitive data:
only the attacker's own IP, counts, and the usernames they tried. Key is read from ABUSEIPDB_KEY in the protected environment.

Usage: abuse_report.py [--dry]   print what it would send (default)
       abuse_report.py --submit  send reports to AbuseIPDB
"""
import collections, datetime as dt, importlib.util, json, os, sys, time, urllib.error, urllib.parse, urllib.request

spec = importlib.util.spec_from_file_location("digest", os.path.join(os.path.dirname(__file__), "digest.py"))
digest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(digest)

WINDOW_H = 24          # how far back to aggregate each run
REPORT_EVERY_H = 24    # don't re-report the same IP more often than this
STATE = "/var/lib/honeypot-report/abuseipdb.json"
API = "https://api.abuseipdb.com/api/v2/report"
DRY = "--submit" not in sys.argv or "--dry" in sys.argv


def key():
    value = os.environ.get("ABUSEIPDB_KEY", "").strip()
    if not value:
        raise SystemExit("set ABUSEIPDB_KEY in the protected service environment")
    return value


def load_state():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {}


def save_state(s):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    json.dump(s, open(tmp, "w"))
    os.replace(tmp, STATE)


def collect():
    """{ip: {logins, cmds, files, users, proto, last}} for outside visitors in the window."""
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=WINDOW_H)
    out = {}
    for e in digest.events(since):
        ip = e.get("src_ip", "")
        # Do not submit operator-configured masked or non-public addresses to the external service.
        if not ip or ip in digest.TELNET_MASK_IPS or digest.is_private(ip):
            continue
        d = out.setdefault(ip, {"logins": 0, "cmds": 0, "files": 0, "users": collections.Counter(),
                                "proto": set(), "last": "", "dreq": 0, "dcreates": 0, "descapes": 0,
                                "redis_rce": 0})
        ev = e.get("eventid", "")
        if ev == "cowrie.session.connect":
            d["proto"].add(e.get("protocol", "ssh"))
        elif ev in ("cowrie.login.success", "cowrie.login.failed"):
            d["logins"] += 1
            if e.get("username"):
                d["users"][str(e["username"])] += 1
        elif ev == "cowrie.command.input":
            d["cmds"] += 1
        elif ev in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            d["files"] += 1
        ts = e.get("timestamp", "")
        if ts > d["last"]:
            d["last"] = ts
    # Docker API honeypot abusers (dockerpot): report IPs that actually tried a container-create
    dk = digest.docker(since)
    dc = collections.Counter(c["ip"] for c in dk["creates"])
    de = collections.Counter(x.split(":")[0].strip() for x in dk["escapes"])
    for ip, n in dk["ips"].items():
        if not ip or ip in digest.TELNET_MASK_IPS or digest.is_private(ip):
            continue
        d = out.setdefault(ip, {"logins": 0, "cmds": 0, "files": 0, "users": collections.Counter(),
                                "proto": set(), "last": "", "dreq": 0, "dcreates": 0, "descapes": 0,
                                "redis_rce": 0})
        d["dreq"], d["dcreates"], d["descapes"] = n, dc.get(ip, 0), de.get(ip, 0)
    # Redis API honeypot abusers (redispot): report IPs that attempted RCE (CONFIG SET dir / SLAVEOF / MODULE LOAD)
    rr = digest.redis(since)
    for ip in rr["rce_ips"]:
        if not ip or ip in digest.TELNET_MASK_IPS or digest.is_private(ip):
            continue
        d = out.setdefault(ip, {"logins": 0, "cmds": 0, "files": 0, "users": collections.Counter(),
                                "proto": set(), "last": "", "dreq": 0, "dcreates": 0, "descapes": 0,
                                "redis_rce": 0})
        d["redis_rce"] += 1
    return out


def categories(d):
    # AbuseIPDB ids: 18 brute-force, 22 ssh, 23 iot-targeted, 15 hacking, 20 exploited host, 14 port scan
    cats = []
    if d["logins"] or d["cmds"] or d["files"]:
        cats += ["18", "22"]
        if "telnet" in d["proto"]:
            cats.append("23")
    if d["cmds"] or d["files"] or d.get("dcreates") or d.get("descapes") or d.get("redis_rce"):
        cats.append("15")
    if d["files"] or d.get("dcreates") or d.get("descapes") or d.get("redis_rce"):
        cats.append("20")
    return ",".join(dict.fromkeys(cats)) or "14"


def comment(d):
    parts = []
    if d["logins"]:
        parts.append(f"{d['logins']} SSH/Telnet login attempts")
    if d["cmds"]:
        parts.append(f"{d['cmds']} commands run after login")
    if d["files"]:
        parts.append(f"{d['files']} file transfer(s)")
    if d.get("dcreates"):
        parts.append(f"{d['dcreates']} Docker API container-create attempts (cryptojacking)")
    if d.get("descapes"):
        parts.append(f"{d['descapes']} Docker host-filesystem escape attempt(s)")
    if d.get("redis_rce"):
        parts.append(f"{d['redis_rce']} Redis RCE attempts (CONFIG SET dir / SLAVEOF / MODULE LOAD)")
    s = ("; ".join(parts) + " in the last 24h.") if parts else "honeypot abuse in the last 24h."
    users = ", ".join(u for u, _ in d["users"].most_common(6))
    if users:
        s += f" Usernames tried: {users}."
    s += " (automated report from an SSH/Docker honeypot)"
    return s[:1024]


def report(ip, cats, cmt, last, k):
    data = urllib.parse.urlencode({"ip": ip, "categories": cats, "comment": cmt, "timestamp": last}).encode()
    req = urllib.request.Request(API, data, {"Key": k, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main():
    state = load_state()
    now = time.time()
    k = None if DRY else key()
    sent = skipped = 0
    for ip, d in sorted(collect().items(), key=lambda kv: kv[1]["last"], reverse=True):
        # a bare TCP connect with no auth attempt is a scan, not SSH abuse (and many are legit
        # internet scanners like Shodan/Censys) - don't report those as brute-force.
        if (d["logins"] == 0 and d["cmds"] == 0 and d["files"] == 0
                and d.get("dcreates", 0) == 0 and d.get("redis_rce", 0) == 0):
            continue
        if now - state.get(ip, 0) < REPORT_EVERY_H * 3600:
            skipped += 1
            continue
        cats, cmt = categories(d), comment(d)
        last = d["last"] or dt.datetime.now(dt.timezone.utc).isoformat()
        if DRY:
            print(f"{ip:16} cats={cats:14} | {cmt}")
            continue
        try:
            res = report(ip, cats, cmt, last, k)
            score = res.get("data", {}).get("abuseConfidenceScore", "?")
            print(f"reported {ip} cats={cats} -> confidence {score}")
            state[ip] = now
            sent += 1
        except urllib.error.HTTPError as ex:
            body = ex.read().decode(errors="replace")[:200]
            print(f"{ip}: HTTP {ex.code} {body}")
            if ex.code == 429:  # rate-limited or daily cap reached; stop and keep the rest for next run
                break
        except Exception as ex:
            print(f"{ip}: {type(ex).__name__}: {ex}")
    if not DRY:
        save_state(state)
    print(f"done: {sent} reported, {skipped} still within the {REPORT_EVERY_H}h window")


if __name__ == "__main__":
    main()
