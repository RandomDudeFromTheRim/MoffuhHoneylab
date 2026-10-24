# Setup and deployment

These files are templates. They are not installed or activated automatically. Use a dedicated Raspberry Pi or disposable VM, review filesystem paths, and keep private configuration outside Git.

## Requirements

- Linux with Python 3.10+ and standard-library modules.
- systemd and nftables for the included service and jail examples.
- Docker Engine with Compose plugin for Cowrie and the Paper bait.
- Node.js and npm for optional Mineflayer decoys.
- A compatible Cowrie image and, for the bait filesystem generator, its matching Cowrie Python package.
- A Paper server JAR and CoreProtect plugin for the real Minecraft bait. They are not included.

Review Cowrie's current upstream image and the Minecraft container image before deployment. Compose files use mutable tags; pin reviewed versions or digests for production.

## 1. Configure private values

Copy .env.example to .env and set local values. On Linux:

    cp .env.example .env
    chmod 600 .env

Choose unused, non-overlapping Docker subnets. Set COWRIE_DATA_DIR and MCBAIT_DATA_DIR to dedicated persistent storage. Generate a unique RCON password, for example with openssl rand -hex 32, then set the same value for RCON_PASSWORD and MCPOT_RCON_PASSWORD. Never reuse an account password.

The example binds Cowrie's published ports to loopback. If your router forwards public ports directly to the Pi, set HONEYPOT_BIND_ADDRESS to the Pi's LAN address and allow only planned inbound ports in the host firewall. Standalone systemd services bind all interfaces and need firewall review before use.

Do not set MC_EULA_ACCEPTED=TRUE until you have read and accepted the Minecraft EULA. Provide a locally obtained Paper JAR at MCBAIT_DATA_DIR/paper.jar and install a compatible CoreProtect plugin. No game binary or plugin is included.

## 2. Review network isolation

Inspect current nftables state and routes first. Confirm Docker bridge interfaces are named br-hp-cowrie and br-hp-mcbait, and chosen subnets do not conflict. Review IPv6 and local DNS behavior. Validate the example before applying:

    sudo nft --check --file deploy/firewall/honeypot-jail.nft

The sample denies bridge-initiated traffic to listed local and special-use ranges while permitting public egress. It is not a complete host firewall and may need adaptation to routing, metadata services, DNS, VPNs, or IPv6. Do not replace an existing firewall ruleset blindly. Integrate the table with your current policy and test that containers cannot reach the Pi, LAN, management plane, or other private networks.

Router mappings in the README are examples only. Keep Paper backend port 25567 and RCON 25575 loopback-only. Never forward those ports from the Internet.

## 3. Start Compose components deliberately

From the repository root, preview and start Cowrie after reviewing its data volume and egress policy:

    docker compose --env-file .env -f deploy/compose/cowrie/docker-compose.yml config
    docker compose --env-file .env -f deploy/compose/cowrie/docker-compose.yml up -d

To enable the optional custom Cowrie filesystem, copy cowrie/build_bait.py into the mounted Cowrie var/custom directory, run it inside the Cowrie container, and then apply the example override:

    docker cp cowrie/build_bait.py honeypot-cowrie:/cowrie/cowrie-git/var/custom/build_bait.py
    docker exec honeypot-cowrie python /cowrie/cowrie-git/var/custom/build_bait.py
    docker compose --env-file .env -f deploy/compose/cowrie/docker-compose.yml -f deploy/compose/cowrie/docker-compose.bait.example.yml up -d

The generator writes synthetic Cowrie filesystem and process-list data into the Cowrie data volume. It does not create a real cloud credential or make an outbound callback.

The Paper Compose service requires a real data directory and an explicit EULA setting. It runs offline with no whitelist; do not start it on a trusted or production network. Its world is intentionally disposable.

## 4. Install standalone listeners and systemd templates

The example units assume installation at /opt/honeypot-lab. If you use another path, edit ExecStart and the firewall file path. Put protected environment settings in /etc/honeypot-lab/honeypot.env and set permissions to 0600. The Minecraft watcher has its own /etc/honeypot-lab/mcbait.env because it needs explicit data and wipe configuration; deploy/systemd/mcbait.env.example is a starting point. It may also read the optional shared honeypot.env for reporting integrations.

Install only selected units, review their sandbox settings and log access, then run systemd-analyze verify against them before enabling them. Do not enable mcbait-watcher.timer until you have reviewed the data path and deliberately set MCBAIT_ALLOW_WIPE=YES. The watcher can delete the configured world and CoreProtect database. Its sample environment sets MCBAIT_ALLOW_WIPE=NO.

Set the firewall table up before starting network-facing containers. No service is enabled by this release bundle.

## 5. Optional integrations

- LLM summary: set ROUTERAI_API_KEY, HONEYPOT_LLM_BASE_URL, and HONEYPOT_LLM_MODEL. The digest sends selected commands, attempted passwords, Docker command text, and Minecraft names to that endpoint. Use --no-rate to skip it.
- Muffar Discord reporting: the daily digest and threshold-triggered Minecraft wipe report use the existing Discord bot REST integration. Set DISCORD_BOT_TOKEN and numeric DISCORD_OUTPUT_CHANNEL_ID in a protected environment. The digest posts only when explicitly run with --post; the wipe watcher posts only after explicit wipe opt-in. The client/reporting code is included, but the separate Muffar bot application and its credentials are not.
- AbuseIPDB: abuse_report.py is dry-run by default. Inspect output, then add --submit only when you intend to send reports.
- DShield: disabled by default in the Cowrie Compose file. Enabling it sends Cowrie source IP data to the feed.
- MalwareBazaar: mb_submit.py info HASH looks up a hash. mb_submit.py upload FILE sends the selected file. Uploads are manual and should be reviewed first.
- Minecraft chat bots: install dependencies with npm ci in minecraft/bots. Without LLM variables, clients use fixed greetings and do not call an external model.

See [operations.md](operations.md) for data-sharing details and safe reporting guidance.
