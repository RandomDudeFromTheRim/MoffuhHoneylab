#!/usr/bin/env python3
"""Monitor a disposable Paper bait server and optionally reset its world.

The watcher reads the CoreProtect database and local Minecraft door log. A threshold-triggered wipe is
possible only when MCBAIT_ALLOW_WIPE=YES is explicitly set; only named paths below MCBAIT_DATA_DIR are
removed. Docker Compose controls the bait server lifecycle.
"""
import collections, importlib.util, json, os, shutil, sqlite3, subprocess, sys, tempfile, time
from pathlib import Path

DATA = os.environ.get("MCBAIT_DATA_DIR")
COMPOSE_DIR = os.environ.get("MCBAIT_COMPOSE_DIR", str(Path(__file__).resolve().parents[1] / "deploy" / "compose" / "minecraft"))
DB = os.path.join(DATA, "plugins/CoreProtect/database.db") if DATA else None
STATE = os.environ.get("MCBAIT_STATE", "/var/lib/mcbait/state.json")
REPORTS = os.environ.get("HONEYPOT_REPORT_DIR", "/var/lib/honeypot-lab/reports")
MC_LOG = os.environ.get("MCPOT_LOG", "/var/lib/mcpot/events.jsonl")
WIPE_PATHS = ["world", "world_nether", "world_the_end", "plugins/CoreProtect/database.db", "usercache.json"]
# "wrecked" = any of these since the last wipe (players' own block changes, explosions, griefer staples)
LIMITS = {"player_blocks": 4000, "explosion_blocks": 800, "tnt_placed": 40, "lava_placed": 40, "fire_placed": 60}
MAX_AGE_DAYS = 7   # also wipe a world this old if anybody played in it
GRIEF_MIN = 10     # a real "griefer" changed >=10 blocks - not someone who just logged in and punched a mob
# our three decoy players, the self-test client, and operator-configured names are omitted:
# and their building never triggers a wipe
BOTS = tuple(dict.fromkeys(("LabPlayerOne", "LabPlayerTwo", "LabFarmer", "SelfTestBot") + tuple(v.strip() for v in os.environ.get("HONEYPOT_EXCLUDED_MC_NAMES", "").split(",") if v.strip())))

spec = importlib.util.spec_from_file_location("digest", str(Path(__file__).resolve().parents[1] / "cowrie" / "digest.py"))
digest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(digest)


def load_state():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {"since": time.time(), "wipes": 0}


def save_state(s):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    json.dump(s, open(tmp, "w"), indent=1)
    os.replace(tmp, STATE)


def query(sql, args=()):
    """Run against a copy of CoreProtect's DB, so the live server is never locked or disturbed."""
    if not DB or not os.path.exists(DB):
        return []
    with tempfile.TemporaryDirectory() as d:
        shutil.copy(DB, f"{d}/db")
        con = sqlite3.connect(f"{d}/db")
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()


def stats():
    q = lambda sql: query(sql)
    mat = """(SELECT material FROM co_material_map m WHERE m.id = b.type)"""
    player = "u.user NOT LIKE '#%' AND u.user NOT IN (" + ", ".join(f"'{b}'" for b in BOTS) + ")"
    s = {}
    s["players"] = (q(f"SELECT COUNT(DISTINCT s.user) FROM co_session s JOIN co_user u ON u.id = s.user "
                      f"WHERE s.action = 1 AND {player}") or [[0]])[0][0]
    s["sessions"] = (q("SELECT COUNT(*) FROM co_session WHERE action = 1") or [[0]])[0][0]
    rows = q(f"SELECT b.action, {mat}, u.user FROM co_block b JOIN co_user u ON u.id = b.user")
    placed, broken, by_user, boom = collections.Counter(), collections.Counter(), collections.Counter(), 0
    for action, m, user in rows:
        m = (m or "?").replace("minecraft:", "")
        if user in BOTS:
            continue
        if user.startswith("#"):
            if user in ("#tnt", "#creeper", "#explosion", "#tntminecart", "#end_crystal") and action == 0:
                boom += 1
            continue
        by_user[user] += 1
        (placed if action == 1 else broken if action == 0 else collections.Counter())[m] += 1
    s["player_blocks"] = sum(placed.values()) + sum(broken.values())
    s["explosion_blocks"] = boom
    s["tnt_placed"] = placed["tnt"]
    s["lava_placed"] = placed["lava"]
    s["fire_placed"] = placed["fire"]
    s["top_placed"] = placed.most_common(8)
    s["top_broken"] = broken.most_common(8)
    s["top_users"] = by_user.most_common(10)
    s["griefers"] = sum(1 for _, c in by_user.items() if c >= GRIEF_MIN)   # actually tore up/built >=10 blocks
    s["names"] = [r[0] for r in q(f"SELECT u.user FROM co_user u WHERE {player} ORDER BY u.time")][:40]
    s["chat"] = [f"<{u}> {m}" for u, m in q("SELECT u.user, c.message FROM co_chat c JOIN co_user u ON u.id = c.user "
                                             "ORDER BY c.time DESC LIMIT 15")][::-1]
    s["commands"] = collections.Counter(
        m.split()[0] for (m,) in q("SELECT message FROM co_command") if m).most_common(10)
    s["stolen"] = (q("SELECT COALESCE(SUM(amount), 0) FROM co_container WHERE action = 0") or [[0]])[0][0]
    return s


def wrecked(s, state):
    hit = [k for k, lim in LIMITS.items() if s.get(k, 0) >= lim]
    if not hit and s["players"] and time.time() - state.get("since", time.time()) > MAX_AGE_DAYS * 86400:
        hit = [f"world older than {MAX_AGE_DAYS} days"]
    return hit


def ips_since(since):
    ips, joins = set(), 0
    try:
        for line in open(MC_LOG, errors="replace"):
            e = json.loads(line)
            if e.get("ts", 0) >= since and e.get("type") == "join" and not digest.is_private(e.get("ip", "")):
                ips.add(e["ip"])
                joins += 1
    except (OSError, ValueError):
        pass
    return ips, joins


def report(s, state, reasons):
    since = state.get("since", time.time())
    ips, joins = ips_since(since)
    age_h = (time.time() - since) / 3600
    head = [
        f"Bait Minecraft server, world #{state.get('wipes', 0) + 1}: {age_h:.0f} h old",
        f"Reason: {', '.join(reasons) if reasons else 'status only (not wiped)'}",
        f"Players: {s['players']} ({s['sessions']} logins), real griefers (>={GRIEF_MIN} blocks): {s['griefers']}, "
        f"join attempts at the door: {joins} from {len(ips)} IPs",
        f"Blocks changed by players: {s['player_blocks']}, blown up: {s['explosion_blocks']}, "
        f"TNT placed: {s['tnt_placed']}, lava: {s['lava_placed']}, fire: {s['fire_placed']}, items stolen: {s['stolen']}",
    ]
    fmt = lambda pairs: ", ".join(f"{k} {v}" for k, v in pairs) or "none"
    body = head + [
        "", f"Who did the most: {fmt(s['top_users'])}",
        f"Most placed: {fmt(s['top_placed'])}",
        f"Most broken: {fmt(s['top_broken'])}",
        f"Commands tried: {fmt(s['commands'])}",
        f"Usernames: {', '.join(s['names']) or 'none'}",
        "", "Last chat:", *([f"  {digest.clip(c, 150)}" for c in s["chat"]] or ["  (none)"]),
    ]
    rater = []
    if s["players"]:
        rater = digest.llm(
            "Below are stats from a deliberately exposed, disposable Minecraft server that griefers and bots "
            f"joined and wrecked before it was wiped. LabPlayerOne, LabPlayerTwo and LabFarmer are the server's own "
            f"decoy bots posing as regulars; their chat lines are ours, react to how visitors treated them. Write at most 5 short lines. {digest.TONE} Say what they "
            "mostly did, who was the worst offender and how, anything notable in chat or commands, and "
            "optionally one dry remark.\n\n" + "\n".join(body), max_lines=6)
    return head, body, rater


def compose(*args):
    return subprocess.run(["docker", "compose", *args], cwd=COMPOSE_DIR, capture_output=True, text=True, timeout=300)


def wipe(state):
    """Delete only the configured disposable world paths, after explicit operator opt-in."""
    if os.environ.get("MCBAIT_ALLOW_WIPE") != "YES":
        raise SystemExit("refusing world wipe: set MCBAIT_ALLOW_WIPE=YES after reviewing the data path")
    if not DATA:
        raise SystemExit("refusing world wipe: set MCBAIT_DATA_DIR to the disposable world directory")
    data_root = os.path.realpath(DATA)
    if data_root == os.path.abspath(os.sep) or not os.path.isdir(data_root):
        raise SystemExit("refusing world wipe: data directory must exist and cannot be filesystem root")
    r = compose("stop")
    if r.returncode != 0:
        raise SystemExit("could not stop mcbait: " + r.stderr[-300:])
    for rel in WIPE_PATHS:
        p = os.path.realpath(os.path.join(data_root, rel))
        try:
            inside = os.path.commonpath((data_root, p)) == data_root
        except ValueError:
            inside = False
        if not inside or p == data_root:
            raise SystemExit(f"refusing to delete {p}: outside {data_root}")
        if os.path.isdir(p):
            shutil.rmtree(p)
        elif os.path.exists(p):
            os.remove(p)
    r = compose("up", "-d")
    if r.returncode != 0:
        raise SystemExit("world was wiped but mcbait did not restart: " + r.stderr[-300:])
    state.update(since=time.time(), wipes=state.get("wipes", 0) + 1, last_wipe=time.time())


def publish(head, body, rater, state, reasons):
    os.makedirs(REPORTS, exist_ok=True)
    name = f"{REPORTS}/mcbait-{time.strftime('%Y%m%d-%H%M')}.txt"
    with open(name, "w", newline="\r\n") as f:
        f.write("\n".join(body + ["", "The rater (optional LLM):", *(rater or ["  (nobody played)"])]) + "\n")
    short = head + ([""] + [l.strip() for l in rater] if rater else [])
    try:
        digest.send_discord("🧨 **bait server wrecked, wiping it**\n```\n" +
                            digest.clip("\n".join(short).replace("```", "'''"), 1850) + "\n```")
    except Exception as e:
        print(f"Discord post failed: {type(e).__name__}: {e}")
    return name


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    state = load_state()
    s = stats()
    reasons = wrecked(s, state)
    state["stats"] = {k: s[k] for k in ("players", "griefers", "sessions", "player_blocks", "explosion_blocks",
                                       "tnt_placed", "lava_placed", "fire_placed", "stolen")}
    state["checked"] = time.time()
    if cmd == "status":
        print(json.dumps(state, indent=1))
    elif cmd == "report":
        head, body, rater = report(s, state, reasons)
        print("\n".join(body + ["", *rater]))
    elif cmd == "wipe" or (cmd == "check" and reasons):
        reasons = reasons or ["manual wipe"]
        if os.environ.get("MCBAIT_ALLOW_WIPE") != "YES":
            print("wipe threshold reached; no report or deletion performed (set MCBAIT_ALLOW_WIPE=YES to opt in)")
        else:
            head, body, rater = report(s, state, reasons)
            name = publish(head, body, rater, state, reasons)
            wipe(state)
            print(f"wiped ({', '.join(reasons)}); report {name}")
    save_state(state)


if __name__ == "__main__":
    main()
