# Running VulnClaw in Docker

The image bundles the Python CLI, the built React Web UI, and the runtimes
(`npx` + `uvx`) needed by the default MCP servers (`memory`, `fetch`). All
mutable state (config, sessions, targets, reports) is kept in a `/data` volume.

## Quick start (docker compose)

```bash
cp .env.example .env          # add your VULNCLAW_LLM_API_KEY
docker compose up --build      # builds the image and starts the Web UI
```

Then open <http://127.0.0.1:7788>.

State persists in the `vulnclaw-data` named volume across restarts.

## Quick start (plain docker)

```bash
# Build
docker build -t vulnclaw:latest .

# Run the Web UI (persisting state in a named volume)
docker run --rm -it \
  -p 127.0.0.1:7788:7788 \
  -e VULNCLAW_LLM_API_KEY=sk-your-key-here \
  -v vulnclaw-data:/data \
  vulnclaw:latest
```

## Running CLI commands instead of the Web UI

The entrypoint is the `vulnclaw` binary, so you can override the command:

```bash
# One-off scan (replace TARGET)
docker run --rm -it \
  -e VULNCLAW_LLM_API_KEY=sk-your-key-here \
  -v vulnclaw-data:/data \
  vulnclaw:latest scan TARGET

# Interactive REPL / TUI
docker run --rm -it \
  -e VULNCLAW_LLM_API_KEY=sk-your-key-here \
  -v vulnclaw-data:/data \
  vulnclaw:latest repl

# Show help / available subcommands
docker run --rm vulnclaw:latest --help
```

With compose:

```bash
docker compose run --rm vulnclaw scan TARGET
```

## Configuration

Configuration is supplied via environment variables (see `.env.example`) and/or
the persisted `config.yaml` written into the `/data` volume. Environment
variables override the config file at startup.

## Scanning a target from inside the container

`localhost` / `127.0.0.1` inside the container refers to the **container
itself**, not your host or another container - so scanning `localhost:PORT`
will never reach a service running elsewhere. Use a routable address instead:

- **Target on your host** (e.g. a `pnpm dev` / `npm run dev` server): add a
  host-gateway alias and target `host.docker.internal`:

  ```yaml
  services:
    vulnclaw:
      extra_hosts:
        - "host.docker.internal:host-gateway"
  ```

  Then scan `host.docker.internal:3000`. Note many dev servers bind to
  loopback only (`127.0.0.1` / `[::1]`); start them on `0.0.0.0`
  (e.g. `--host 0.0.0.0`) or the container still won't reach them.

- **Target in another container**: put both on the same Docker network and
  scan it by **container/service name** (e.g. `targetapp:8080`):

  ```yaml
  services:
    vulnclaw:
      networks: [default, targetnet]
  networks:
    targetnet:
      external: true
      name: <the-target-project's-network>   # `docker network ls`
  ```

Verify reachability before scanning:

```bash
docker compose exec vulnclaw \
  python -c "import socket; socket.create_connection(('TARGET', PORT), 3); print('reachable')"
```

## Notes

- The container binds the Web UI to `0.0.0.0` internally (required for the
  published port to be reachable); the host-side `127.0.0.1:7788` mapping keeps
  it private to your machine. Change the mapping to expose it elsewhere - only
  do so on networks you trust, as the UI has no authentication.
- The `chrome-devtools` MCP server is disabled by default; enabling it requires
  a Chrome/Chromium browser which is not installed in this image to keep it
  lean.
- The optional knowledge-base feature (`kb`, ChromaDB) is not installed by
  default. Add `kb` to the `pip install` extras in the Dockerfile if you need it.
