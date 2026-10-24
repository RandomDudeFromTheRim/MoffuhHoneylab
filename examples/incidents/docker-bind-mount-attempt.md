# Synthetic incident: Docker host bind-mount attempt

## Observation

A synthetic POST to /containers/create requested a placeholder image, omitted command payload, and asked to bind the host root at /host. DockerPot logs the request body and returns a synthetic container ID.

## Effect

DockerPot did not contact Docker Engine, create a container, mount a host path, or execute the command. A 201-style response is fabricated. This is a recorded attempt, not a successful host escape.

## Useful indicators

- Endpoint: POST /containers/create.
- Bind attempt: /:/host:ro.
- Evidence: examples/events/dockerpot.jsonl.
