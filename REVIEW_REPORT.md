# Release review report

## Scope inspected

The workspace is a collection of folders, not a single honeypot Git checkout. The selected implementation folders were redispot/, dockerpot/, cowrie/, tarpit/, mcbait/, and mcpot/. The only copied dashboard integration is the narrowly scoped Homepage widget structure that calls Cowrie's honeystats.py API.

The selected honeypot folders contain no .git metadata, so no project history was available there. Separate Git repositories elsewhere in the workspace concern unrelated projects and were excluded from this release bundle. No history was copied.

## Potential secrets and personal infrastructure values found

- cowrie/build_bait.py contains a hard-coded AWS access-key/secret pair described in the source as a live canary credential. At the owner's explicit direction, the staging copy retains the existing canary values in the generated bait filesystem. The owner acknowledges and accepts this exposure risk for this release. No rotation, revocation, provider lookup, activity review, or safety verification was performed; this report makes no claim that the credential is safe or active.
- Source files contained personal host/router/proxy IP literals, filesystem mount paths, a home-directory path to private bot config, an LLM provider endpoint, operational notes about a proxy test, and a Minecraft username the source comments identified as another person's account. These were replaced or removed in the release copy; deployment locations and integrations use environment variables, loopback defaults, .invalid placeholders, or synthetic usernames. The sample event IPs use RFC 5737 documentation ranges.
- Apart from the intentionally retained AWS canary pair described above, no populated .env file, Discord webhook URL, Discord bot token, non-AWS integration API key, private-key file, or session token was present in the selected source folders. Integration code referred to credentials stored outside those folders; no external config was copied.
- The Cowrie generator also had a fixed bait password. The release copy generates a fresh random value for each synthetic filesystem build.

## Files excluded and reasons

- Raw attacker event logs, runtime state JSON, Cowrie downloads, generated fs.pickle and process-list artifacts, malware samples, populated .env files, and private operator config files: not included. The accepted canary credential remains in the Cowrie bait source as described above; release events are synthetic.
- mcbait/bots/make-env.sh: omitted because it read a secret from a personal bot configuration path and wrote a live service environment file. A generic environment-variable setup is documented instead.
- banviewer/: no Cowrie/honeypot integration was found in its source; it is a separate IP/blocklist dashboard.
- The full homepage/ tree: contains unrelated services, host addresses, and credentials. Only an anonymized honeypot widget example was recreated.
- Gateway, proxy, network experiment, personal notes, host lists, unrelated Compose files, and the separate publish/repo project: outside the honeypot release scope.
- No user logs or captured payloads were used to create the event examples. The separate bot repository/application is not present in the selected source folders; the existing Muffar Discord reporting client in digest/watcher code is included with env-only credentials.

## Network-facing findings and release-copy changes

| Finding | Change in this release copy | Remaining concern |
|---|---|---|
| Redis parser allowed many individually large arguments, lacked an aggregate payload cap, command timeout, and connection cap. | Added a 1 MiB aggregate command cap, argument/line limits, 30-second read timeout, and 128-connection admission cap. | Event files can still grow without rotation; OS connection and file-descriptor limits remain necessary. |
| DockerPot read an unbounded Content-Length and used an unbounded thread-per-connection server with no per-socket timeout. | Added a 1 MiB request-body limit, rejects transfer-encoded bodies, caps workers at 64, sets a 15-second socket timeout, and clips query data in logs. | Each accepted event can still log up to 1 MiB of attacker-controlled content. Rotate logs and restrict access. |
| MCPot used a semaphore that bounded active protocol work but could leave accepted handlers queued while clients waited. | Added a hard 128-connection admission cap, retained packet/read/idle limits, and tightened string parsing. | A configured upstream is a real Minecraft server; isolate it and configure only a local bait destination. |
| Tarpit defaulted to as many as 4,096 held sockets. | Lowered default to 256, clamps configurable maximum to 1,024 and delay to 1–300 seconds. | It intentionally holds real sockets and can still consume resources up to its cap. |
| Honeystats used an unbounded thread-per-request HTTP server, a cache keyed by arbitrary query strings, and included attempted passwords in its feed. | Loopback bind by default, bounded workers and socket timeout, cache by known route, and password-free feed. | Feed still contains source IPs and other event text; keep remote access private/authenticated. |
| Optional Mineflayer LLM call had a timeout but read the entire response body into memory and attempted calls when its base/model settings were incomplete. | Added a 1 MiB streaming response cap and require key, base URL, and model before making calls. | The configured LLM endpoint is still an outbound data-sharing dependency; endpoint quality and retention are operator concerns. |
| Minecraft watcher could automatically wipe on a timer, and its data-boundary check used string-prefix comparison. | Requires explicit MCBAIT_ALLOW_WIPE=YES, uses commonpath after resolving paths, and checks the Compose restart result. | When enabled, it really deletes selected world/cache paths under the configured data root and invokes Docker. Review backups and paths before opting in. |
| Cowrie bait builder includes an AWS canary credential and previously used a fixed bait password. | Retained the existing canary values in the staging generator at the owner's explicit direction; bait password remains randomly generated per build. | Accepted risk for this release. Credential status, rotation, revocation, and provider activity were not checked. |
| Digest/report code scans log files and some aggregation results scale with input volume and unique attacker-controlled values. Cowrie captures are also stored on disk. | No broad retention or report-window cap was applied because changing aggregation behavior needs operator requirements. | Enforce log rotation, disk quotas, and Cowrie capture retention; consider bounded event windows and cardinality caps. |
| Minecraft watcher copies the CoreProtect database before calculating stats. | No size cap added because truncating/partially copying SQLite state could give incorrect results. | Monitor database size and available temporary disk before enabling the timer. |

Other relevant behavior: Cowrie can make outbound fetches to URLs supplied through its emulated shell; optional DShield, LLM, Discord, AbuseIPDB, and MalwareBazaar integrations make external requests. See SECURITY.md and docs/operations.md.

## Verification performed

- Python syntax compilation, runtime-safe imports, Node.js syntax checking, JSON/JSONL parsing, and Compose YAML parsing are recorded below after the final edits. The Cowrie bait generator was syntax-checked but not imported because importing it executes its filesystem-generation code.
- Release-only secret-pattern and infrastructure scans were run against the final staging tree. The scan is expected to find the one owner-accepted AWS canary key/secret pair; example events use synthetic data and reserved documentation IP ranges.
- No captured payloads were executed. No network deployment, publishing, push, or running Pi service modification was performed.

### Verification results

- PASS: Python compile() syntax check for all 10 Python files.
- PASS: imports for 9 runtime-safe modules; build_bait.py was syntax-checked only because importing it executes its filesystem-generation routine.
- PASS: LICENSE finalized as MIT with Copyright (c) 2026 moffer, per owner instruction.
- PASS: Node.js --check for minecraft/bots/bots.js.
- PASS: parsed all 9 JSON/schema files, all 5 JSONL example files, and all 4 YAML files.
- PASS: final release-only scan (58 files) found no populated .env files, private-key blocks, Discord webhook URLs, or searched personal identity/endpoint markers. It found the single intentionally retained AWS canary credential pair, which is recorded as an owner-accepted risk; no other likely credential match was found. Reserved documentation IP ranges and deliberate wildcard/loopback/config subnet addresses remain in examples/templates.
- NOT RUN: Docker, nftables, or systemd-native validation tools were unavailable in this Windows environment; no integration/runtime behavior tests were run.

## Accepted risk (not a publication blocker per owner direction)

The existing AWS canary access-key/secret pair is retained in the Cowrie bait generator. The owner acknowledged and accepted this risk for this release. No rotation, revocation, provider activity review, or safety verification is claimed.

## Remaining deployment decisions

1. Pin and review Cowrie/Minecraft image tags and confirm current source dependencies.
2. Validate firewall rules, service permissions, disk quotas/log rotation, and port mappings on an isolated test host before deployment.
3. Decide whether to enable any LLM, Discord, DShield, AbuseIPDB, or MalwareBazaar data sharing.
4. Supply/verify the Paper JAR and CoreProtect version and accept the Minecraft EULA only if appropriate.
