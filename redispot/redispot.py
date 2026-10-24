#!/usr/bin/env python3
"""Low-interaction Redis honeypot (zgw-redispot.service, :6379).

Bots scan 6379 for an unauthenticated Redis, then abuse it for RCE: `CONFIG SET dir` + `CONFIG SET
dbfilename` + `SET` a cron/SSH-key payload + `SAVE` (writes a cron job that runs their miner), or
`SLAVEOF`/`REPLICAOF` a malicious master + `MODULE LOAD`. This EMULATES the RESP protocol and does NOTHING:
it never writes a file, never saves, never loads a module, makes no outbound connection. It answers
plausibly and logs every command - above all the SET payload (miner pool+wallet / payload URL), the
CONFIG SET dir/dbfilename, and the SLAVEOF master.

Themed as an old unprotected Redis 5.0.7. Log: /var/lib/redispot/events.jsonl
"""
import asyncio, datetime as dt, json, os

LOG = os.environ.get("REDISPOT_LOG", "/var/lib/redispot/events.jsonl")
BIND = os.environ.get("REDISPOT_BIND", "0.0.0.0")
PORT = int(os.environ.get("REDISPOT_PORT", "6379"))
MAX_ARGS = 128
MAX_BULK = 1 << 20          # 1 MiB per argument cap
MAX_COMMAND_BYTES = 1 << 20 # total bulk data per command
MAX_CONNECTIONS = 128
COMMAND_TIMEOUT = 30
_ACTIVE_CONNECTIONS = 0

INFO = (
    "# Server\r\nredis_version:5.0.7\r\nredis_git_sha1:00000000\r\nredis_mode:standalone\r\n"
    "os:Linux 5.15.0-1042-raspi x86_64\r\narch_bits:64\r\nprocess_id:1\r\nrun_id:" + os.urandom(20).hex() +
    "\r\ntcp_port:6379\r\nuptime_in_seconds:184052\r\nconfig_file:\r\n"
    "# Clients\r\nconnected_clients:1\r\n"
    "# Memory\r\nused_memory:874592\r\nused_memory_human:854.09K\r\nmaxmemory:0\r\n"
    "# Persistence\r\nloading:0\r\nrdb_bgsave_in_progress:0\r\naof_enabled:0\r\n"
    "# Replication\r\nrole:master\r\nconnected_slaves:0\r\nmaster_replid:" + os.urandom(20).hex() +
    "\r\n# CPU\r\nused_cpu_sys:120.50\r\n"
    "# Keyspace\r\ndb0:keys=3,expires=0,avg_ttl=0\r\n")

CONFIG = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb", "maxmemory": "0",
          "save": "3600 1 300 100 60 10000", "requirepass": "", "bind": "0.0.0.0",
          "protected-mode": "no", "appendonly": "no"}


def logrec(rec):
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def dec(b):
    return b.decode("utf-8", "replace")


def bulk(s):
    b = s.encode() if isinstance(s, str) else s
    return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"


def reply(args):
    """Raw RESP bytes for one command. Emulates; writes/saves/loads NOTHING."""
    if not args:
        return b"+OK\r\n"
    cmd = dec(args[0]).upper()
    if cmd == "PING":
        return bulk(args[1]) if len(args) > 1 else b"+PONG\r\n"
    if cmd == "INFO":
        return bulk(INFO.encode())
    if cmd == "AUTH":
        return b"+OK\r\n"                       # look unprotected / accept any password
    if cmd == "BGSAVE":
        return b"+Background saving started\r\n"
    if cmd == "BGREWRITEAOF":
        return b"+Background append only file rewriting started\r\n"
    if cmd == "CONFIG":
        sub = dec(args[1]).upper() if len(args) > 1 else ""
        if sub == "GET":
            key = dec(args[2]).lower() if len(args) > 2 else ""
            items = []
            if key in CONFIG:
                items = [key, CONFIG[key]]
            elif "*" in key or not key:
                for k, v in CONFIG.items():
                    items += [k, v]
            out = b"*" + str(len(items)).encode() + b"\r\n"
            for it in items:
                out += bulk(it)
            return out
        return b"+OK\r\n"                       # CONFIG SET / REWRITE / RESETSTAT -> fake success
    if cmd == "GET":
        return b"$-1\r\n"                       # nil
    if cmd in ("DBSIZE", "EXISTS", "DEL", "TTL", "PTTL", "UNLINK"):
        return b":0\r\n"
    if cmd == "MODULE":
        sub = dec(args[1]).upper() if len(args) > 1 else ""
        if sub == "LIST":
            return b"*0\r\n"
        return b"-ERR Error loading the extension. Please check the server logs.\r\n"
    if cmd in ("COMMAND", "KEYS", "SCAN"):
        return b"*0\r\n" if cmd != "SCAN" else b"*2\r\n$1\r\n0\r\n*0\r\n"
    if cmd == "TYPE":
        return b"+none\r\n"
    if cmd in ("HELLO", "SUBSCRIBE", "PSUBSCRIBE"):
        return b"-ERR unknown command '" + args[0] + b"'\r\n"
    # SET / SETEX / SELECT / SAVE / SLAVEOF / REPLICAOF / FLUSHALL / RENAME / CLIENT / QUIT / everything
    # else -> +OK, to keep the attacker running their whole chain so we capture all of it.
    return b"+OK\r\n"


async def read_command(reader):
    line = await reader.readline()
    if not line:
        return None
    if len(line) > 8192 or not line.endswith(b"\n"):
        return None
    line = line.rstrip(b"\r\n")
    if not line:
        return []
    if line[:1] != b"*":
        return line.split()
    try:
        n = int(line[1:])
    except ValueError:
        return None
    if n < 0 or n > MAX_ARGS:
        return None
    args = []
    total = 0
    for _ in range(n):
        hdr = await reader.readline()
        if len(hdr) > 32 or not hdr.startswith(b"$") or not hdr.endswith(b"\n"):
            return None
        try:
            ln = int(hdr[1:].strip())
        except ValueError:
            return None
        if ln < 0 or ln > MAX_BULK or total + ln > MAX_COMMAND_BYTES:
            return None
        total += ln
        data = await reader.readexactly(ln)
        if await reader.readexactly(2) != b"\r\n":
            return None
        args.append(data)
    return args


async def _handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "?"
    try:
        while True:
            try:
                args = await asyncio.wait_for(read_command(reader), timeout=COMMAND_TIMEOUT)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError, ValueError):
                break
            if args is None:
                break
            if args:
                logrec({"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "src_ip": ip,
                        "cmd": [dec(a)[:2000] for a in args]})
                quit_now = dec(args[0]).upper() == "QUIT"
            else:
                quit_now = False
            writer.write(reply(args))
            await writer.drain()
            if quit_now:
                break
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def handle(reader, writer):
    global _ACTIVE_CONNECTIONS
    if _ACTIVE_CONNECTIONS >= MAX_CONNECTIONS:
        writer.close()
        return
    _ACTIVE_CONNECTIONS += 1
    try:
        await _handle_client(reader, writer)
    finally:
        _ACTIVE_CONNECTIONS -= 1


async def main():
    os.makedirs(os.path.dirname(LOG) or ".", exist_ok=True)
    server = await asyncio.start_server(handle, BIND, PORT, limit=8192, backlog=128)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
