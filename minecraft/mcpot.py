#!/usr/bin/env python3
"""Minecraft protocol front door that logs connection handshakes and can proxy to a bait server.

When MCPOT_UPSTREAM is configured, joiners interact with a real disposable Paper world. Without an
upstream, the service answers pings and rejects join attempts. It does not execute commands on the host.
"""
import asyncio, json, os, struct, time, uuid

BIND = os.environ.get("MCPOT_BIND", "0.0.0.0")
PORT = int(os.environ.get("MCPOT_PORT", "25566"))
UPSTREAM = os.environ.get("MCPOT_UPSTREAM", "")    # e.g. 127.0.0.1:25567; empty = answer locally
LOG = os.path.join(os.environ.get("STATE_DIRECTORY", "/var/lib/mcpot"), "events.jsonl")
MAX_CONN = 128          # hard cap on accepted connections
MAX_PACKET = 32768      # bytes; real handshake/login packets are tiny
TIMEOUT = 10            # seconds per read before the handshake is done
IDLE = 600              # seconds without traffic before a relayed session is cut
MOTD = "§aExample SMP §7| §e1.21 §7| §bsurvival"
FAKE_PLAYERS = ["LabPlayerOne", "LabPlayerTwo", "LabFarmer"]
KICK = "You are not whitelisted on this server!"
_active_connections = 0


def log(ev):
    ev["ts"] = time.time()
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except OSError:
        pass


class Rec:
    """Wraps a StreamReader and keeps every byte read, so it can be replayed to the bait server."""

    def __init__(self, r):
        self.r, self.buf = r, bytearray()

    async def readexactly(self, n):
        b = await asyncio.wait_for(self.r.readexactly(n), TIMEOUT)
        self.buf += b
        return b


async def varint(r):
    n = 0
    for i in range(5):
        b = (await r.readexactly(1))[0]
        n |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return n
    raise ValueError("varint too long")


def read_varint(buf, pos):
    n = 0
    for i in range(5):
        b = buf[pos]; pos += 1
        n |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return n, pos
    raise ValueError("varint too long")


def read_str(buf, pos):
    n, pos = read_varint(buf, pos)
    if n > 1024:
        raise ValueError("string too long")
    if pos + n > len(buf):
        raise ValueError("truncated string")
    return buf[pos:pos + n].decode("utf-8", "replace"), pos + n


def enc_varint(n):
    out = bytearray()
    n &= 0xFFFFFFFF
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def enc_str(s):
    b = s.encode()
    return enc_varint(len(b)) + b


def packet(pid, data=b""):
    body = enc_varint(pid) + data
    return enc_varint(len(body)) + body


async def read_packet(r, first=None):
    n = await varint(r) if first is None else first
    if n <= 0 or n > MAX_PACKET:
        raise ValueError(f"bad length {n}")
    buf = await r.readexactly(n)
    pid, pos = read_varint(buf, 0)
    return pid, buf, pos


async def open_upstream():
    if not UPSTREAM:
        return None
    host, port = UPSTREAM.rsplit(":", 1)
    try:
        return await asyncio.wait_for(asyncio.open_connection(host, int(port)), 3)
    except (OSError, asyncio.TimeoutError):
        return None


async def pipe(src, dst):
    try:
        while True:
            b = await asyncio.wait_for(src.read(65536), IDLE)
            if not b:
                break
            dst.write(b)
            await dst.drain()
    except (OSError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def relay(rec, w, up, ev):
    """Replay what we read to the bait server and pipe both ways until either side closes."""
    ur, uw = up
    uw.write(bytes(rec.buf))
    await uw.drain()
    ev["relayed"] = True
    t0 = time.time()
    await asyncio.gather(pipe(rec.r, uw), pipe(ur, w))
    ev["secs"] = round(time.time() - t0, 1)


async def _handle_client(r, w):
    ip = (w.get_extra_info("peername") or ("?",))[0]
    ev = {"ip": ip}
    rec = Rec(r)
    try:
        b0 = (await rec.readexactly(1))[0]
        if b0 == 0xFE:  # legacy (pre-1.7) ping, still used by some scanners
            ev["type"] = "legacy_ping"
            s = "§1\x00127\x001.21\x00" + MOTD + "\x003\x0020"
            w.write(b"\xff" + struct.pack(">H", len(s)) + s.encode("utf-16-be"))
            await w.drain()
            return
        # first byte was the start of a varint length
        n = b0 & 0x7F
        if b0 & 0x80:
            rest = await varint(rec)
            n |= rest << 7
        pid, buf, pos = await read_packet(rec, n)
        if pid != 0:
            ev["type"] = "junk"
            return
        proto, pos = read_varint(buf, pos)
        host, pos = read_str(buf, pos)
        port = struct.unpack(">H", buf[pos:pos + 2])[0]; pos += 2
        nxt, pos = read_varint(buf, pos)
        ev.update(proto=proto, host=host[:100], port=port)
        if nxt == 1:
            ev["type"] = "ping"
            up = await open_upstream()
            if up:
                await relay(rec, w, up, ev)
                return
            await read_packet(rec)  # status request
            status = {"version": {"name": "1.21.4", "protocol": proto},
                      "players": {"max": 20, "online": len(FAKE_PLAYERS),
                                  "sample": [{"name": p, "id": str(uuid.uuid3(uuid.NAMESPACE_DNS, p))}
                                             for p in FAKE_PLAYERS]},
                      "description": {"text": MOTD}, "enforcesSecureChat": False}
            w.write(packet(0, enc_str(json.dumps(status))))
            await w.drain()
            try:
                pid, buf, pos = await read_packet(rec)
                if pid == 1:
                    w.write(packet(1, buf[pos:pos + 8]))
                    await w.drain()
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                pass
        elif nxt in (2, 3):
            ev["type"] = "join"
            pid, buf, pos = await read_packet(rec)
            if pid == 0:
                name, pos = read_str(buf, pos)
                ev["name"] = name[:32]
                if len(buf) - pos >= 16:  # 1.19+ sends the player's UUID too
                    ev["uuid"] = str(uuid.UUID(bytes=bytes(buf[pos:pos + 16])))
            log(dict(ev, type="join_start"))  # so a long game session shows up before it ends
            up = await open_upstream()
            if up:
                await relay(rec, w, up, ev)
                return
            w.write(packet(0, enc_str(json.dumps({"text": KICK}))))
            await w.drain()
        else:
            ev["type"] = f"state{nxt}"
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        ev.setdefault("type", "dropped")
    except (ValueError, IndexError, struct.error) as e:
        ev.setdefault("type", "malformed")
        ev["err"] = str(e)[:60]
    finally:
        log(ev)
        try:
            w.close()
        except Exception:
            pass


async def handle(r, w):
    global _active_connections
    if _active_connections >= MAX_CONN:
        w.close()
        return
    _active_connections += 1
    try:
        await _handle_client(r, w)
    finally:
        _active_connections -= 1


async def main():
    os.makedirs(os.path.dirname(LOG) or ".", exist_ok=True)
    srv = await asyncio.start_server(handle, BIND, PORT, limit=MAX_PACKET, backlog=128)
    print(f"mcpot listening on {PORT}, upstream {UPSTREAM or 'none'}, logging to {LOG}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
