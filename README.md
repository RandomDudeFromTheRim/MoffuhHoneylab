# Raspberry Pi Honeypot Lab

A public release bundle of low-interaction deception services and a disposable Minecraft bait server, assembled from the working project files. It is licensed under MIT; nothing has been published from this staging directory.

> **These are deception services, not real Docker or Redis servers.** RedisPot emulates RESP replies and writes no Redis data. DockerPot is a plain HTTP responder and never calls the Docker Engine. Cowrie presents a fake shell. Minecraft is different: when configured, MCPot relays visitors to a real, disposable Paper server whose world they can change.

## Components

| Component | What it records | What it actually does |
|---|---|---|
| RedisPot | RESP commands, including configuration, replication, and payload attempts | Simulates replies. It does not persist data, load modules, execute commands, or connect outbound. |
| DockerPot | Docker API paths, queries, and bounded request bodies | Returns synthetic API responses. It does not open a Docker socket, create containers, or connect outbound. |
| Cowrie helpers | SSH/Telnet events, commands, file transfer metadata, digests, and optional reports | Cowrie is an external container image supplying a fake shell. It may fetch attacker-provided URLs and stores files in its data volume; this bundle does not run downloaded samples. |
| SSH tarpit | Connection times and generated banner-line counts | Holds real TCP connections and sends non-SSH lines until the client closes or the configured cap is reached. |
| MCPot | Minecraft handshake, source, requested host, protocol, and join identity | Answers pings and rejects joins without an upstream; otherwise proxies the session to the bait server. |
| Minecraft bait and watcher | CoreProtect world-change statistics and join counts | Operates a real Paper server in offline mode. Players can change its disposable world. Wiping requires MCBAIT_ALLOW_WIPE=YES. |
| Mineflayer decoys | Local bot activity and optionally game chat sent to an LLM | Runs three game clients against the bait server. LLM use is off unless configured. |
| Honeystats API and Homepage example | Aggregated counts and a short visitor feed | Read-only API bound to loopback by default. Keep it on a trusted network. |
| Digest and reporting helpers | Cross-service counts and selected event text | Writes a local report. Optional LLM, Discord, AbuseIPDB, DShield, and MalwareBazaar functions can make real outbound requests when enabled. |

Architecture is in [docs/architecture.md](docs/architecture.md). Setup and operations are in [docs/setup.md](docs/setup.md) and [docs/operations.md](docs/operations.md). Event formats are in [docs/logging.md](docs/logging.md).

## Quick orientation

1. Read [SECURITY.md](SECURITY.md) and [REVIEW_REPORT.md](REVIEW_REPORT.md) before deploying.
2. Review .env.example, select non-overlapping Docker subnets, configure paths, and create a private .env with mode 0600. Never commit it.
3. Put captured logs and samples on quota-limited storage. Do not copy existing Pi logs or captured artifacts into this repository.
4. Review the sample nftables jail and integrate it with the host's existing firewall. Do not load it blindly.
5. Start only the components you intend to expose. Compose defaults bind Cowrie and Minecraft host ports to loopback. Standalone services bind all interfaces, so firewall them before starting.
6. Do not forward Paper 25567 or RCON 25575 from the Internet. Public Minecraft traffic should reach MCPot on 25566 only.

No installer, service activation, public publishing, or deployment action is performed by this repository. Templates require local path, permission, firewall, and operating-system review. See [docs/setup.md](docs/setup.md).

## Network and outbound behavior

| Internet-facing port | Local listener | Service |
|---:|---:|---|
| TCP 22 | 2222 | Cowrie SSH |
| TCP 23 | 2223 | Cowrie Telnet |
| TCP 2375 | 2375 | DockerPot simulation |
| TCP 6379 | 6379 | RedisPot simulation |
| TCP 2222 | 2200 | SSH tarpit |
| TCP 25565 | 25566 | MCPot Minecraft front door |

These are examples, not router commands. Do not expose other host services by copying this table. Read the egress and privacy notes in [docs/operations.md](docs/operations.md).

## Canary credential in Cowrie bait

The Cowrie bait filesystem generator retains the existing AWS canary credential so the simulated `~/.aws/credentials` file preserves its canary behavior. The project owner has acknowledged and accepted this exposure risk for this release. The credential was not checked, rotated, revoked, or verified safe. Operators forking or deploying this project should use a canary they own and review its provider configuration.

## Logs and examples

Logs are JSON Lines where possible. They contain source IPs, user-entered names, attempted passwords, commands, paths, and payload text. Treat them as sensitive, attacker-controlled data. Do not publish raw event logs. Files under [examples/events/](examples/events/) are synthetic; incident write-ups under [examples/incidents/](examples/incidents/) distinguish observed attempts from successful effects.

## Limitations

- RedisPot and DockerPot are deliberately incomplete protocol models. A bot can detect differences from real servers.
- Cowrie is a fake shell and does not prove that a real host was compromised. Its emulation can still make outbound downloads when configured.
- Tarpit connections consume real sockets, memory, and file descriptors despite the cap.
- MCPot parses only the protocol paths implemented in its source. An upstream Paper session is a real application session, not a simulation.
- Paper runs offline with no whitelist in the provided example. Anyone who reaches it may join and modify the world. It must remain disposable and isolated.
- Reports can be incomplete when log rotation, permissions, or paths differ from the templates. External feeds and LLM summaries are optional and can be unavailable or incorrect.
- Docker image tags are mutable in the inherited examples. Pin and review image versions or digests before long-running deployment.

## License

This project is licensed under the MIT License. Copyright (c) 2026 moffer. See [LICENSE](LICENSE) for the terms.
