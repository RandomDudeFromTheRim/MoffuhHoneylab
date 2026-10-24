# Security and responsible operation

## Purpose and scope

This repository contains deception services for systems you own or are explicitly authorized to monitor. Deploy them on an isolated host, VLAN, or disposable VM. Do not use them to access, disrupt, or retaliate against other systems.

RedisPot and DockerPot are protocol emulators, not real Redis or Docker daemons. DockerPot never opens the Docker socket, creates a container, or runs a submitted command. RedisPot does not write files, save a database, load a module, or execute a submitted payload. Cowrie provides a fake shell. MCPot can relay sessions to an actual Paper server; Minecraft players can alter that server's world.

## Safe operation

- Keep the honeypot host separate from personal, production, and management systems. Use a dedicated network and deny access from honeypot containers to private and special-use ranges.
- Review deploy/firewall/honeypot-jail.nft against current nftables rules, bridge names, local routes, IPv6 configuration, DNS behavior, and required outbound destinations before loading it.
- Do not expose SSH administration, Docker Engine, RCON, Paper's backend port, dashboards, or log files as honeypot services.
- Run RedisPot, DockerPot, and the tarpit without elevated privileges. The mcbait watcher needs Docker control access; Docker group membership is effectively root. Keep it disabled until its data path and wipe behavior are reviewed.
- The world watcher deletes configured world directories and the CoreProtect database after thresholds are met only when MCBAIT_ALLOW_WIPE=YES is explicitly set. Keep this unset or set to NO until you deliberately opt in.
- Configure resource caps, log rotation, disk quotas, and retention. A successful log write does not imply a successful attack.
- Treat attacker-controlled text, URLs, archives, and captured files as untrusted. Do not execute or install samples. Inspect them in an isolated analysis environment.
- A Cowrie session can request downloads from attacker-controlled URLs. The jail example allows public Internet egress to support this behavior; restrict outbound traffic further if downloads are not needed.

## Accepted release risk: Cowrie canary bait

The Cowrie bait builder retains the existing AWS canary access-key/secret pair in the generated fake filesystem. The project owner has explicitly accepted its inclusion for this release. No rotation, revocation, provider lookup, activity review, or safety verification was performed. The code does not claim the credential is safe. A fork or deployment should use a canary owned by its operator.

## Data sharing and privacy

Logs may contain IP addresses, attempted credentials, usernames, chat, commands, and malware URLs. The digest can send selected commands, attempted passwords, Docker command text, and Minecraft usernames to the configured LLM provider. Discord reports may include selected summary data. DShield and AbuseIPDB can receive observed source IPs and report metadata. MalwareBazaar upload sends a selected file to its service. Integrations are disabled or manual by default in this release bundle; enabling them is an operator decision. Review applicable rules and your privacy policy first.

The dashboard API exposes visitor IPs and event text through /feed. It binds to 127.0.0.1 by default; protect remote access with a firewall or authenticated reverse proxy.

## Reporting suspected vulnerabilities

For a vulnerability in this code, provide a minimal reproduction, affected component, impact, and suggested mitigation through GitHub private vulnerability reporting or a private security advisory when available. Do not include live credentials, raw attacker logs, or malware samples in a public issue. This repository does not identify a project-specific security contact yet.
