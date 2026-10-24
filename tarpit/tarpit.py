#!/usr/bin/env python3
"""endlessh-style SSH tarpit (zgw-tarpit.service, :2200).

An SSH client waits for the server's identification line ("SSH-2.0-...") before it does anything. This
service never sends it: it accepts the connection and dribbles a random, non-"SSH-" banner line every
DELAY seconds, forever, so the scanner's worker thread hangs until its own (often absent) timeout fires.
Pure time-waster, pre-auth - it captures no commands; the point is to pin scanner threads and log how long
we held them. Makes no outbound connection. asyncio holds thousands of stuck sockets cheaply.

Router forward (user's job): WAN 2222 -> 0.0.0.0:2200.
Log: /var/lib/tarpit/events.jsonl    Live state: /var/lib/tarpit/state.json
"""
import asyncio, datetime as dt, json, os, random, secrets, time

LOG = os.environ.get("TARPIT_LOG", "/var/lib/tarpit/events.jsonl")
STATE = os.environ.get("TARPIT_STATE", "/var/lib/tarpit/state.json")
BIND = os.environ.get("TARPIT_BIND", "0.0.0.0")
PORT = int(os.environ.get("TARPIT_PORT", "2200"))
DELAY = min(300.0, max(1.0, float(os.environ.get("TARPIT_DELAY", "10"))))
MAX_CONN = min(1024, max(1, int(os.environ.get("TARPIT_MAX", "256"))))

_open = {}                        # id -> (ip, start_epoch)
_life = {"conns": 0, "held_s": 0.0}
_ALPHABET = b"0123456789abcdefABCDEF !#$%&*+-=/"


def logrec(rec):
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def save_state():
    oldest = min((s for _, s in _open.values()), default=0)
    try:
        with open(STATE + ".tmp", "w") as f:
            json.dump({"open": len(_open), "oldest_ts": oldest,
                       "lifetime_conns": _life["conns"], "lifetime_held_s": round(_life["held_s"])}, f)
        os.replace(STATE + ".tmp", STATE)
    except OSError:
        pass


async def handle(reader, writer):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "?"
    if len(_open) >= MAX_CONN:            # at capacity: drop so a flood can't exhaust the Pi
        try:
            writer.close()
        except OSError:
            pass
        return
    cid = secrets.token_hex(6)
    start = time.time()
    _open[cid] = (ip, start)
    _life["conns"] += 1
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    logrec({"ts": now, "src_ip": ip, "event": "connect", "id": cid})
    save_state()
    lines = 0
    try:
        while True:
            # a random line that is NOT the "SSH-2.0-" identification the client is waiting for
            n = random.randint(4, 40)
            writer.write(bytes(random.choice(_ALPHABET) for _ in range(n)) + b"\r\n")
            await writer.drain()
            lines += 1
            await asyncio.sleep(DELAY)
    except (ConnectionError, asyncio.CancelledError, OSError, TimeoutError):
        pass
    finally:
        held = time.time() - start
        _open.pop(cid, None)
        _life["held_s"] += held
        logrec({"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "src_ip": ip, "event": "close",
                "id": cid, "held_s": round(held, 1), "lines": lines})
        save_state()
        try:
            writer.close()
        except OSError:
            pass


async def main():
    os.makedirs(os.path.dirname(LOG) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(STATE) or ".", exist_ok=True)
    save_state()
    server = await asyncio.start_server(handle, BIND, PORT, backlog=128)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
