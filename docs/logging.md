# Log schemas and reports

All examples in examples/events/ are generated, sanitized fixtures using documentation-only IP ranges and reserved .invalid hosts. They are not copied from production logs.

## Event formats

Machine-readable JSON Schemas are in [docs/schemas/](schemas/). They describe common event fields; Cowrie can add event-specific properties.

| Source | Format | Main fields |
|---|---|---|
| Cowrie | JSONL from Cowrie JSON output | timestamp, eventid, session, src_ip, protocol, plus event-specific username, password, input, url, filename, or shasum. Cowrie controls exact event variants. |
| RedisPot | One JSON object per line | ts (UTC ISO string), src_ip, cmd (decoded argument list; each string clipped to 2,000 characters). |
| DockerPot | One JSON object per HTTP request | ts, src_ip, method, path, optional query (clipped), optional body (accepted body is at most 1 MiB). |
| MCPot | One JSON object per connection/event | ts (Unix seconds), ip, type; optional proto, host, port, name, uuid, relayed, secs, and short parser err. A long join can produce join_start followed by join. |
| Tarpit | One JSON object per connect/close | ts, src_ip, event, id; close events add held_s and lines. state.json separately stores current open count and lifetime totals. |
| mcbait watcher | JSON state file and local text reports | State includes wipe count, time bounds, latest check, and aggregated world statistics. Reports may include usernames and chat; treat them as sensitive. |

## Event notes

- cowrie.login.success means Cowrie accepted credentials into its emulated shell. It is not a successful login to the host operating system.
- DockerPot logs attempted request bodies. A 201 response is synthetic; no container was created.
- RedisPot logs commands. A simulated +OK does not mean Redis performed the requested action.
- MCPot's join records an observed client join attempt or session. When relayed is true, the session was forwarded to the configured Paper bait server.
- Tarpit connect and close records are measurements of real TCP connections held by the service.

## Reports and dashboard

cowrie/digest.py aggregates SSH/Telnet, Redis, Docker, tarpit, and Minecraft events. By default its optional LLM rater is disabled unless all LLM environment variables are configured; --no-rate disables it explicitly. Discord is contacted only with --post and a configured bot token/channel. honeystats.py provides /cowrie, /minecraft, /docker, /redis, /tarpit, and /feed JSON routes for an internal dashboard.

The dashboard /feed omits attempted passwords, but may still expose source IPs, usernames, commands, URLs, and chat-derived labels. Keep it private. The digest and reports may contain more sensitive event text than the dashboard.
