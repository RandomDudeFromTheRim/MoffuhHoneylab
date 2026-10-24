# Release notes

## Proposed public release bundle

### Included

- RedisPot, DockerPot, and SSH tarpit implementations.
- Cowrie helpers: bait filesystem generator, daily digest, internal stats API, AbuseIPDB report helper, and manual MalwareBazaar helper. The Muffar Discord reporting client is retained as environment-configured REST integration; the separate Discord bot application is not bundled.
- Minecraft MCPot front door, disposable Paper watcher, and optional Mineflayer decoy clients.
- Cowrie and Minecraft Compose examples; systemd service/timer templates; nftables container-jail example; internal Homepage widget example.
- Synthetic JSONL events, incident write-ups, architecture/setup/operations/logging guidance, .gitignore, .env.example, security policy, and the selected MIT license.

### Redactions and safety changes in this release copy

- Retained the existing AWS canary access key and secret in the Cowrie bait generator at the owner's explicit direction. The owner acknowledges and accepts this public-release risk; the credential was not checked, rotated, revoked, or declared safe.
- Replaced personal IPs, mount locations, host aliases, private integration config paths, operational proxy-test notes, and non-project Minecraft usernames with generic settings, loopback defaults, environment variables, and synthetic identities.
- Omitted the source make-env.sh helper that extracted a live LLM key from a separate personal bot configuration. The release uses documented protected environment variables instead.
- Removed raw operational logs, state files, captured downloads, generated Cowrie pickle files, populated .env files, and unrelated dashboard/gateway configuration.
- Added request, worker, socket, connection, parser, and cache bounds to network-facing services; bounded the optional Mineflayer LLM response to 1 MiB; made the dashboard loopback-only by default.
- Changed AbuseIPDB reporting to dry-run by default and require --submit for network submission.
- Added explicit MCBAIT_ALLOW_WIPE=YES gating and stricter path containment to the destructive Minecraft world wipe. The code still stops the bait Compose service, deletes selected paths under the configured data root, and restarts it when enabled.
- Removed attempted passwords from the dashboard visitor feed.

### Known limitations

- The staging copy has not been deployed to a Raspberry Pi. Host firewall, systemd permissions, Docker routing, RCON behavior, Cowrie version compatibility, and Minecraft plugin behavior still need operator validation.
- Cowrie and Minecraft image tags are mutable; pin and review image versions or digests before long-term use.
- The Minecraft bait requires a locally supplied Paper JAR, CoreProtect plugin, and deliberate EULA acceptance.
- The nftables jail is an example and needs review against target-host IPv4/IPv6 routes, DNS, bridges, and existing firewall.
- MIT was selected by the project owner. LICENSE is completed with Copyright (c) 2026 moffer.
