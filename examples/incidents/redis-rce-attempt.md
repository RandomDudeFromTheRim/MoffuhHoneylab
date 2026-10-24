# Synthetic incident: Redis persistence and cron attempt

## Observation

A documentation-only source address issued CONFIG SET for a cron directory, set a cron-like value, then sent SAVE. RedisPot logged the command sequence and returned simulated acknowledgements.

## Effect

No file was written, no cron job was created, no save occurred, and no payload ran. This event is an attempted Redis exploitation chain against a protocol emulator, not a successful compromise.

## Useful indicators

- Commands: CONFIG SET dir, SET, SAVE.
- Source address: synthetic RFC 5737 example range.
- Evidence: examples/events/redispot.jsonl.
