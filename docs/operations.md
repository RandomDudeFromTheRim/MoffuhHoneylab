# Operations and security review notes

## What the listeners do

- RedisPot accepts RESP arrays and inline commands, logs bounded command data, and returns synthetic replies. SAVE, CONFIG SET, SLAVEOF, MODULE LOAD, and similar commands do not change files or run anything.
- DockerPot serves a synthetic Docker Engine API over HTTP. Create/start/exec calls return plausible IDs and output while doing no container operation. Its systemd template denies AF_UNIX and marks Docker sockets inaccessible.
- Cowrie is an external container that emulates SSH/Telnet login and shell behavior. It can make actual outbound fetches when attackers request downloads. Captured files are inert from this bundle's perspective, but remain malware.
- Tarpit holds up to its configured cap of sockets and periodically writes random non-SSH banner lines. It consumes real resources and can delay legitimate clients if ports are mapped incorrectly.
- MCPot logs a handshake and either answers locally or proxies to MCPOT_UPSTREAM. A proxied join reaches a real Paper process. Players can alter or destroy the disposable world. The watcher may stop Compose, delete only its listed world/cache paths under MCBAIT_DATA_DIR, and start a new world after explicit opt-in.

## Resource and parser bounds in this release copy

- Redis command: 128 arguments, at most 1 MiB aggregate bulk data, 1 MiB per argument, 8 KiB lines, 30-second command read timeout, and 128 concurrent connections.
- DockerPot: 1 MiB request-body cap, no chunked request bodies, 64 concurrent worker threads, 15-second socket timeout, and capped query data in logs.
- MCPot: 32 KiB packet cap, bounded strings, per-read handshake timeouts, relay idle timeout, and hard admission cap of 128 connections.
- Tarpit: default 256 concurrent sockets, hard configured maximum 1,024, and delay clamped to 1–300 seconds.
- Honeystats: loopback default, 16 worker threads, 5-second socket timeout, known-route cache keys, and a feed that no longer displays attempted passwords.

These are application limits, not a substitute for OS limits, firewalling, log rotation, storage quotas, monitoring, or rate controls.

## Outbound traffic and data sharing

| Component | Possible outbound activity |
|---|---|
| RedisPot, DockerPot, tarpit | None in the implementation. |
| Cowrie | Attacker-requested downloads may contact public URLs. Optional DShield reporting can send source IP data. |
| MCPot | Connects only to configured MCPOT_UPSTREAM; keep it pointed at the local bait server. |
| Mineflayer bots | Connect to the bait server. If configured, chat excerpts go to an LLM endpoint and generated replies go in-game. |
| Digest | Optional LLM receives selected commands, attempted passwords, Docker command text, Minecraft names, and bait-server chat excerpts. Optional Discord posting sends a report summary. |
| AbuseIPDB helper | --submit sends observed public source IPs, categories, counts, and selected attempted usernames. Otherwise it is a dry run. |
| MalwareBazaar helper | info sends a hash lookup; upload sends the selected sample file. There is no timer. |

Review vendor terms, privacy requirements, and event data before enabling sharing. Disable the LLM with --no-rate; omit --post; leave DShield disabled; keep AbuseIPDB in dry-run mode; do not upload files unless reviewed.

## Log handling

Logs grow and may contain passwords, command strings, source IPs, filenames, download URLs, UUIDs, usernames, and Docker body fields. Use restrictive ownership, log rotation or an equivalent bounded collector, disk quotas, and a retention schedule. Compose limits Docker's own container logs, not the JSONL event files. Do not publish runtime logs or send them in public bug reports.

Never pipe captured payloads to a shell, run them in Cowrie, or mount Cowrie downloads into another service. Analyze samples offline in an isolated environment.

## Incident interpretation

An event records what a client sent or attempted. It does not prove that the attacker gained access to the Raspberry Pi, started a Docker container, wrote a Redis file, or compromised a third-party system. For Minecraft, a successful join to Paper is a real game session and may change its disposable world; it still does not mean host-level compromise.

Synthetic examples are in examples/events/. Narrative examples are in examples/incidents/.
