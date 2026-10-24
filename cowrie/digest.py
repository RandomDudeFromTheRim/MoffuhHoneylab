#!/usr/bin/env python3
"""Aggregate Cowrie and companion honeypot logs into a local daily report.

Optional integrations: an OpenAI-compatible LLM endpoint and a Discord bot. Both are disabled unless
credentials and configuration are supplied in the environment; Discord posting also requires --post.
"""
import collections, datetime as dt, glob, ipaddress, json, os, re, sys, urllib.request

LOGS = os.environ.get("COWRIE_LOG_GLOB", "/var/lib/honeypot-lab/cowrie/var/log/cowrie/cowrie.json*")
MC_LOG = os.environ.get("MCPOT_LOG", "/var/lib/mcpot/events.jsonl")
DOCKER_LOG = os.environ.get("DOCKERPOT_LOG", "/var/lib/dockerpot/events.jsonl")
TARPIT_LOG = os.environ.get("TARPIT_LOG", "/var/lib/tarpit/events.jsonl")
TARPIT_STATE = os.environ.get("TARPIT_STATE", "/var/lib/tarpit/state.json")
REDIS_LOG = os.environ.get("REDISPOT_LOG", "/var/lib/redispot/events.jsonl")
OUT = os.environ.get("HONEYPOT_REPORT_DIR", "/var/lib/honeypot-lab/reports")
MC_EXCLUDE = {"labplayerone", "labplayertwo", "labfarmer"} | {v.strip().casefold() for v in os.environ.get("HONEYPOT_EXCLUDED_MC_NAMES", "").split(",") if v.strip()}
TRUSTED_PROXY_IPS = {v.strip() for v in os.environ.get("HONEYPOT_TRUSTED_PROXY_IPS", "").split(",") if v.strip()}
TELNET_MASK_IPS = {v.strip() for v in os.environ.get("HONEYPOT_TELNET_MASK_IPS", "").split(",") if v.strip()}
# Minecraft protocol number -> version, for common protocol IDs.
MC_VERSIONS = {47: "1.8.x", 110: "1.9.4", 210: "1.10.x", 316: "1.11.2", 340: "1.12.2", 404: "1.13.2",
               498: "1.14.4", 578: "1.15.2", 754: "1.16.5", 756: "1.17.1", 758: "1.18.2", 759: "1.19",
               760: "1.19.2", 761: "1.19.3", 762: "1.19.4", 763: "1.20.1", 764: "1.20.2", 765: "1.20.4",
               766: "1.20.6", 767: "1.21.1", 768: "1.21.3", 769: "1.21.4",
               4294967295: "-1 (ping-only scanner)"}


def is_private(ip):
    """Ignore private addresses and operator-configured test/proxy sources."""
    if ip in TRUSTED_PROXY_IPS:
        return True
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


TONE = ("Plain text, no markdown, no emoji. Tone: dry and deadpan, like a bored sysadmin reading logs. "
        "No metaphors, no puns, no 'roast', no exclamation marks, no hype words.")


def llm(prompt, max_lines=14):
    """Optionally call an OpenAI-compatible endpoint; never send data without explicit configuration."""
    key = os.environ.get("ROUTERAI_API_KEY", "").strip()
    base = os.environ.get("HONEYPOT_LLM_BASE_URL", "").strip().rstrip("/")
    model = os.environ.get("HONEYPOT_LLM_MODEL", "").strip()
    if not (key and base and model):
        return ["  (rater disabled: configure the LLM environment variables to enable it)"]
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": 4000}).encode()
    req = urllib.request.Request(f"{base}/chat/completions", body,
                                 {"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read((1 << 20) + 1)
        if len(raw) > (1 << 20):
            raise ValueError("LLM response exceeded 1 MiB")
        text = json.loads(raw)["choices"][0]["message"]["content"].strip()
    except Exception as e:  # the report remains usable if the optional rater is unavailable
        return [f"  (rater failed: {type(e).__name__})"]
    return [f"  {l}" for l in text.splitlines() if l.strip()][:max_lines]


def send_discord(msg):
    """Post a summary using a configured Discord bot token and channel ID."""
    token = os.environ.get("DISCORD_BOT_TOKEN", "").strip()
    channel = os.environ.get("DISCORD_OUTPUT_CHANNEL_ID", "").strip()
    if not token or not channel.isdigit():
        raise RuntimeError("Discord reporting is not configured")
    req = urllib.request.Request(f"https://discord.com/api/v10/channels/{channel}/messages",
                                 json.dumps({"content": msg[:2000], "allowed_mentions": {"parse": []}}).encode(),
                                 {"Authorization": f"Bot {token}", "Content-Type": "application/json",
                                  "User-Agent": "DiscordBot (honeypot-lab, 1)"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status


def clip(s, n):
    return s if len(s) <= n else s[:n - 1] + "…"


def rate(creds, cmds, longest, mc_names, docker_creates=None):
    """Ask the optional LLM endpoint to score the day's bots. Returns lines, or a note on failure."""
    if not cmds and not creds and not mc_names and not docker_creates:
        return ["  (nothing to rate today)"]
    sample = "\n".join([f"{c}x  {k}" for k, c in cmds.most_common(25)] + ["LONGEST:"] + [c[:600] for c in longest])
    pw = ", ".join(k for k, _ in creds.most_common(10))
    names = ", ".join(f"{k} ({c}x)" for k, c in mc_names.most_common(15)) or "none"
    dock = "\n".join(f"{c['image']}: {c['cmd'][:200]}" for c in (docker_creates or [])[:10]) or "none"
    prompt = (
        "Below is what internet bots did to three honeypots in the last day: a fake Linux box (SSH/Telnet), a "
        "Minecraft server (a front door that logs every ping and join attempt), and a fake Docker API "
        "(logs the container-create payloads, where cryptojackers put their miner command). "
        f"Write at most 9 short lines. {TONE} Lines:\n"
        "1) 'creativity N/10, threat N/10'\n"
        "2) what the bots were mostly after, in plain words (crypto miner, botnet loader, recon, ssh key planting...)\n"
        "3) the most dangerous command, quoted short, and what it does\n"
        "4) the dumbest command, quoted short, and why it is pointless\n"
        "5) one line on the Minecraft join attempts (usernames below), if any\n"
        "6) one line on the Docker API attempts (cryptojacking, host-filesystem escape, the image/command), if any\n"
        "7) optionally one short dry remark. Skip it if nothing is actually funny.\n"
        "Skip any line whose data is empty.\n\n"
        f"PASSWORDS TRIED: {pw or 'none'}\n\nCOMMANDS (count, text):\n{sample}\n\nMINECRAFT JOIN USERNAMES: {names}"
        f"\n\nDOCKER API CONTAINER-CREATE ATTEMPTS (image: command):\n{dock}"
    )
    return llm(prompt)


def events(since):
    # Optional masked source values are operator-configured for forwarded/test traffic.
    telnet_masked = set()
    for path in sorted(glob.glob(LOGS)):
        if os.path.getmtime(path) < since.timestamp():
            continue
        with open(path, errors="replace") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    t = dt.datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
                except (ValueError, KeyError):
                    continue
                ip = e.get("src_ip", "")
                if ip in TELNET_MASK_IPS and e.get("eventid") == "cowrie.session.connect" and e.get("protocol") == "telnet":
                    telnet_masked.add(e.get("session"))
                if t >= since and (not is_private(ip) or e.get("session") in telnet_masked):
                    yield e


def minecraft(since):
    """Counters from the Minecraft honeypot log."""
    m = {k: collections.Counter() for k in ("types", "ips", "names", "versions", "hosts")}
    try:
        f = open(MC_LOG, errors="replace")
    except OSError:
        return m
    with f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("ts", 0) < since.timestamp() or is_private(e.get("ip", "")):
                continue
            if (e.get("name") or "").lower() in MC_EXCLUDE:
                continue
            m["types"][e.get("type", "?")] += 1
            m["ips"][e.get("ip", "?")] += 1
            if e.get("name") and e.get("type") == "join":  # join_start is the same join, logged early
                m["names"][e["name"]] += 1
            if "proto" in e:
                m["versions"][MC_VERSIONS.get(e["proto"], f"proto {e['proto']}")] += 1
            if e.get("host"):
                m["hosts"][e["host"]] += 1
    return m


def docker(since):
    """Docker API honeypot (dockerpot): recon + the gold - container-create payloads (image, Cmd, Env,
    host bind mounts) and any miner pool/wallet/payload URL pulled out of them."""
    SENSITIVE = ("/", "/root", "/etc", "/proc", "/sys", "/run", "/var/run", "/host", "/home", "/boot")
    d = {"events": 0, "ips": collections.Counter(), "paths": collections.Counter(),
         "creates": [], "escapes": [], "loot": collections.Counter()}
    try:
        f = open(DOCKER_LOG, errors="replace")
    except OSError:
        return d
    with f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            t, ip = e.get("ts", ""), e.get("src_ip", "")
            if not t or is_private(ip):
                continue
            try:
                when = dt.datetime.fromisoformat(t)
            except ValueError:
                continue
            if when < since:
                continue
            d["events"] += 1
            d["ips"][ip] += 1
            d["paths"][e.get("path", "?")] += 1
            if e.get("path") == "/containers/create" and isinstance(e.get("body"), dict):
                b = e["body"]
                cmd = b.get("Cmd") or b.get("Entrypoint") or []
                cmd = " ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)
                env = b.get("Env") or []
                env = " ".join(map(str, env)) if isinstance(env, list) else str(env)
                image = str(b.get("Image", ""))
                binds = (b.get("HostConfig") or {}).get("Binds") or []
                binds = binds if isinstance(binds, list) else [str(binds)]
                d["creates"].append({"ip": ip, "image": image, "cmd": cmd, "binds": binds})
                for bd in binds:
                    src = str(bd).split(":")[0].rstrip("/") or "/"
                    if src in SENSITIVE or "docker.sock" in str(bd):
                        d["escapes"].append(f"{ip}: {bd}")
                for m in re.finditer(r"stratum\+?(?:tcp|ssl)?://[^\s'\"]+|https?://[^\s'\"]+"
                                     r"|-o\s+\S+|-u\s+\S+|\b4[1-9A-HJ-NP-Za-km-z]{94}\b|\b0x[0-9a-fA-F]{40}\b",
                                     f"{image} {cmd} {env}"):
                    d["loot"][m.group(0).strip()] += 1
    return d


def tarpit(since):
    """SSH tarpit (endlessh-style): how many scanner connections we pinned and for how long. No commands."""
    d = {"conns": 0, "ips": collections.Counter(), "held_s": 0.0, "longest": 0.0, "open": 0, "oldest_ts": 0}
    try:
        f = open(TARPIT_LOG, errors="replace")
    except OSError:
        f = None
    if f:
        with f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                t, ip = e.get("ts", ""), e.get("src_ip", "")
                if not t or is_private(ip):
                    continue
                try:
                    when = dt.datetime.fromisoformat(t)
                except ValueError:
                    continue
                if when < since:
                    continue
                if e.get("event") == "connect":
                    d["conns"] += 1
                    d["ips"][ip] += 1
                elif e.get("event") == "close":
                    hs = e.get("held_s", 0) or 0
                    d["held_s"] += hs
                    d["longest"] = max(d["longest"], hs)
    try:
        s = json.load(open(TARPIT_STATE))
        d["open"], d["oldest_ts"] = s.get("open", 0), s.get("oldest_ts", 0)
    except (OSError, ValueError):
        pass
    return d


def redis(since):
    """Redis honeypot (redispot): commands + the gold - CONFIG SET dir / SET cron payload / SLAVEOF master."""
    d = {"cmds": 0, "ips": collections.Counter(), "rce_ips": set(), "payloads": [], "loot": collections.Counter()}
    try:
        f = open(REDIS_LOG, errors="replace")
    except OSError:
        return d
    with f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            t, ip, cmd = e.get("ts", ""), e.get("src_ip", ""), e.get("cmd") or []
            if not t or is_private(ip) or not cmd:
                continue
            try:
                when = dt.datetime.fromisoformat(t)
            except ValueError:
                continue
            if when < since:
                continue
            d["cmds"] += 1
            d["ips"][ip] += 1
            c0 = cmd[0].upper()
            joined = " ".join(cmd)
            if ((c0 == "CONFIG" and len(cmd) > 2 and cmd[1].upper() == "SET" and cmd[2].lower() in ("dir", "dbfilename"))
                    or c0 in ("SLAVEOF", "REPLICAOF") or (c0 == "MODULE" and len(cmd) > 1 and cmd[1].upper() == "LOAD")):
                d["rce_ips"].add(ip)
            if c0 == "SET" and len(cmd) > 2:
                d["payloads"].append({"ip": ip, "val": cmd[2]})
            if c0 in ("SLAVEOF", "REPLICAOF") and len(cmd) > 1:
                d["loot"]["slaveof " + " ".join(cmd[1:3])] += 1
            if c0 == "MODULE" and len(cmd) > 2:
                d["loot"]["module load " + cmd[2]] += 1
            for m in re.finditer(r"stratum\+?(?:tcp|ssl)?://[^\s'\"]+|https?://[^\s'\"]+|-o\s+\S+|-u\s+\S+"
                                 r"|\b4[1-9A-HJ-NP-Za-km-z]{94}\b|\b0x[0-9a-fA-F]{40}\b", joined):
                d["loot"][m.group(0).strip()] += 1
    return d


def post_discord(summary, rater, creds, cmds, mc, bait, dk=None):
    """Post the short version to Discord bot's output channel. Discord caps a message at 2000 chars."""
    body = [l.strip() for l in summary] + ([bait] if bait else []) + ["", *[l.strip() for l in rater]]
    if creds:
        body += ["", "top passwords:"] + [f"  {c}x {clip(k, 50)}" for k, c in creds.most_common(5)]
    if cmds:
        body += ["top commands:"] + [f"  {c}x {clip(k, 90)}" for k, c in cmds.most_common(6)]
    if mc["names"]:
        body += ["minecraft joiners:"] + [f"  {c}x {clip(k, 32)}" for k, c in mc["names"].most_common(8)]
    if dk and dk["creates"]:
        body += ["docker container creates:"] + [f"  {clip(c['image'] + ': ' + c['cmd'], 90)}" for c in dk["creates"][:4]]
    if dk and dk["loot"]:
        body += ["docker loot:"] + [f"  {clip(k, 85)}" for k, _ in dk["loot"].most_common(5)]
    text = "\n".join(body).replace("```", "'''")
    return send_discord("🍯 **honeypot report**\n```\n" + clip(text, 1900) + "\n```")


def bait_status():
    """One line about the bait Minecraft server, from mcbait.py's last check (state.json)."""
    try:
        s = json.load(open("/var/lib/mcbait/state.json"))
    except (OSError, ValueError):
        return ""
    st = s.get("stats", {})
    return (f"Bait server: world #{s.get('wipes', 0) + 1}, {st.get('players', 0)} players since the last wipe, "
            f"{st.get('player_blocks', 0)} blocks changed by them, {st.get('explosion_blocks', 0)} blown up")


def top(counter, n, width=60):
    return [f"  {c:6d}  {k[:width]}" for k, c in counter.most_common(n)] or ["  (none)"]


def main():
    hours = int(sys.argv[sys.argv.index("--hours") + 1]) if "--hours" in sys.argv else 24
    now = dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(hours=hours)
    ips, creds, users, cmds, clients, proto = (collections.Counter() for _ in range(6))
    logins_ok = logins_bad = sessions = 0
    downloads = {}
    for e in events(since):
        ev = e.get("eventid", "")
        if ev == "cowrie.session.connect":
            sessions += 1
            ips[e.get("src_ip", "?")] += 1
            proto[e.get("protocol", "?")] += 1
        elif ev in ("cowrie.login.success", "cowrie.login.failed"):
            creds[f'{e.get("username")} / {e.get("password")}'] += 1
            users[str(e.get("username"))] += 1
            if ev.endswith("success"):
                logins_ok += 1
            else:
                logins_bad += 1
        elif ev == "cowrie.command.input":
            c = (e.get("input") or "").strip()
            if c:
                cmds[c] += 1
        elif ev == "cowrie.client.version":
            clients[str(e.get("version"))] += 1
        elif ev in ("cowrie.session.file_download", "cowrie.session.file_upload") and e.get("shasum"):
            downloads.setdefault(e["shasum"], (e.get("url") or ("uploaded as " + str(e.get("filename"))) if ev.endswith("upload") else e.get("url") or e.get("destfile") or "?", e.get("src_ip")))
    longest = sorted(cmds, key=len, reverse=True)[:3]
    mc = minecraft(since)
    dk = docker(since)
    tp = tarpit(since)
    rr = redis(since)
    t = mc["types"]
    summary = [
        f"Honeypot digest: last {hours} h, until {now.astimezone():%Y-%m-%d %H:%M %Z}",
        f"SSH/Telnet: {sessions} sessions from {len(ips)} IPs ({', '.join(f'{k} {v}' for k, v in proto.items()) or 'none'})",
        f"Logins: {logins_ok} 'successful' (they got the fake shell), {logins_bad} failed",
        f"Commands typed: {sum(cmds.values())} ({len(cmds)} distinct). Files dropped (downloaded/uploaded): {len(downloads)}",
        f"Minecraft: {t['ping'] + t['legacy_ping']} pings, {t['join']} join attempts "
        f"({len(mc['names'])} usernames) from {len(mc['ips'])} IPs",
        f"Docker API: {dk['events']} requests from {len(dk['ips'])} IPs, {len(dk['creates'])} "
        f"container-create attempts, {len(dk['escapes'])} host-mount escapes",
        f"SSH tarpit: {tp['conns']} scanner connections pinned, {tp['open']} still stuck, "
        f"{tp['held_s'] / 3600:.1f} h of bot time wasted (longest hold {tp['longest'] / 60:.0f} min)",
        f"Redis API: {rr['cmds']} commands from {len(rr['ips'])} IPs, {len(rr['rce_ips'])} IPs attempted RCE",
    ]
    bait = bait_status()
    rater = ["  (skipped)"] if "--no-rate" in sys.argv else rate(creds, cmds, longest, mc["names"], dk["creates"])
    lines = [
        summary[0], "", *summary[1:], *([bait] if bait else []),
        "", "The rater (optional LLM):", *rater,
        "", "Top passwords tried (user / password):", *top(creds, 15),
        "", "Top commands:", *top(cmds, 20, 100),
        "", "Longest command (usually the most unhinged):", *([f"  {c[:400]}" for c in longest] or ["  (none)"]),
        "", "Busiest IPs (SSH/Telnet):", *top(ips, 10),
        "", "SSH clients:", *top(clients, 6),
        "", "Captured downloads (sha256, source):",
        *([f"  {h[:16]}…  {u[:90]}" for h, (u, _) in list(downloads.items())[:15]] or ["  (none)"]),
        "", "Samples: the Cowrie downloads directory (inert files, named by sha256; submit only after review)",
        "", "Minecraft join attempts (username):", *top(mc["names"], 15, 32),
        "", "Minecraft client versions:", *top(mc["versions"], 8),
        "", "Address they typed (IP = mass scanner, a name = found you some other way):", *top(mc["hosts"], 8),
        "", "Busiest IPs (Minecraft):", *top(mc["ips"], 8),
        "", "Minecraft connection types:", *top(mc["types"], 6),
        "", "Docker API honeypot:",
        f"  {dk['events']} requests, {len(dk['creates'])} container creates, {len(dk['escapes'])} host-filesystem escape attempts",
        "", "Container-create payloads (image | command | binds):",
        *([f"  {c['image']}  |  {clip(c['cmd'], 110)}  |  {c['binds']}" for c in dk["creates"][:12]] or ["  (none)"]),
        "", "Host-filesystem escape attempts (bind mounts):", *([f"  {x}" for x in dk["escapes"][:10]] or ["  (none)"]),
        "", "Docker loot (pools / wallets / payload URLs):",
        *([f"  {c:>4}x {k[:100]}" for k, c in dk["loot"].most_common(15)] or ["  (none)"]),
        "", "Busiest IPs (Docker):", *top(dk["ips"], 8),
        "", "SSH tarpit (endlessh-style, pins scanner threads):",
        f"  {tp['conns']} connections pinned, {tp['open']} still stuck now, {tp['held_s'] / 3600:.1f} h wasted "
        f"(longest single hold {tp['longest'] / 60:.1f} min)",
        "", "Busiest IPs (tarpit):", *top(tp["ips"], 8),
        "", "Redis API honeypot:",
        f"  {rr['cmds']} commands, {len(rr['rce_ips'])} IPs attempted RCE (CONFIG SET dir / SLAVEOF / MODULE LOAD)",
        "", "SET payloads (cron / SSH key / miner the bot tried to plant):",
        *([f"  {p['ip']}: {clip(p['val'].replace(chr(10), ' '), 120)}" for p in rr["payloads"][:10]] or ["  (none)"]),
        "", "Redis loot (masters / modules / pools / wallets / URLs):",
        *([f"  {c:>4}x {k[:100]}" for k, c in rr["loot"].most_common(12)] or ["  (none)"]),
        "", "Busiest IPs (Redis):", *top(rr["ips"], 8),
    ]
    text = "\n".join(lines) + "\n"
    if "--stdout" in sys.argv:
        print(text, end="")
        return
    os.makedirs(OUT, exist_ok=True)
    for name in (f"{now.astimezone():%Y-%m-%d}.txt", "latest.txt"):
        with open(os.path.join(OUT, name), "w", newline="\r\n") as f:
            f.write(text)
    print(f"wrote {OUT}/latest.txt: {sessions} ssh sessions, {sum(t.values())} minecraft connections")
    if "--post" in sys.argv:
        try:
            print("posted to Discord:", post_discord(summary, rater, creds, cmds, mc, bait, dk))
        except Exception as e:
            print(f"Discord post failed: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
