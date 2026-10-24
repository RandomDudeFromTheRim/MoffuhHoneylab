# Synthetic incident: Minecraft join and world changes

## Observation

The example MCPot event records a synthetic visitor join at the Minecraft front door. In an actual deployment with MCPOT_UPSTREAM set, a join can be relayed to the disposable Paper server.

## Effect

The sample event alone does not claim that a player joined or changed blocks. In a live setup, Paper can record world edits in CoreProtect and the optional watcher may reset configured world paths after explicit wipe opt-in. This is a real game session, but not evidence of host-level compromise.

## Useful indicators

- Check MCPot join and relayed fields.
- Correlate actual player edits with the local CoreProtect database.
- Evidence format: examples/events/mcpot.jsonl and examples/events/mcbait-state.json.
