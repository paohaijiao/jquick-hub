# jquick-hub (TCP Gateway)

A high-performance **protocol-sniffing TCP gateway** built on **Netty 4**. It exposes a **single public port** and automatically routes inbound connections to different backends based on the first packet:

| Detected protocol | Routing target | Behavior |
|---|---|---|
| **HTTP / HTTPS (TLS)** | Internal Nginx | Transparent pass-through (no parsing, no decryption, no rewriting) |
| **Other plain TCP traffic** (databases, SSH, custom protocols, ...) | Configurable target IP + port | Transparent pass-through, optionally protected by a prefix **magic-token** authentication |

Because the gateway only sniffs and relays raw bytes, it supports arbitrary long-lived TCP protocols (MySQL/PostgreSQL/Oracle, SSH, RDP, custom binary protocols, etc.) with **zero protocol knowledge**.

## Features

- **Single public port, multi-protocol routing** — first-packet protocol sniffing splits traffic between Nginx and other backends.
- **Zero-copy transparent relay** — data is only moved byte-by-byte; never parsed, decrypted, or rewritten.
- **Long-connection friendly** — full-duplex bidirectional relay with:
  - **Zero data loss** while the backend connection is being established (data buffered and flushed atomically once ready);
  - **Close coupling** — if either side disconnects, the other side is closed too;
  - **Backpressure control** — `autoRead` is paused when the peer's write buffer is full, preventing unbounded memory growth;
  - **Reference-count-safe buffering** — no buffer leaks.
- **Prefix magic-token authentication** (optional, for non-HTTP/HTTPS traffic):
  - Fixed-length token prepended to the first business packet, then stripped by the gateway before forwarding;
  - Constant-time token comparison (`MessageDigest.isEqual`) against timing side channels;
  - **Silent close** on auth failure/timeout — no response is sent back, preventing information leakage;
  - Tokens are only logged masked (`first4****last2`), never in plaintext.
- **Graceful shutdown** — `SIGTERM`/`SIGINT` triggers a JVM shutdown hook for clean shutdown.
- **Configurable buffer leak detection** (`SIMPLE | ADVANCED | PARANOID | DISABLED`).
- **Bundled mini-proxy client** (`client/GatewayClient.java`) — lets native tools like Navicat/DBeaver/psql/ssh connect through the gateway with **zero modification**.

## Architecture

```
                    Public network                        Internal network
+----------------+   single port   +------------------+   pass-through   +----------------+
|                |   (e.g. 18080)  |                  |   (no parsing)   |                |
|  HTTP/HTTPS    +---------------->+                  +----------------->+   Nginx        |
|  clients       |                 |   jquick-hub     |                  |   (e.g. :52000)|
|                |                 |  TCP Gateway     |                  |                |
+----------------+                 |                  |                  +----------------+
                                    |                  |
+----------------+   token+data    |                  |   token stripped | +----------------+
| DB/SSH tools   |                 |                  |                  | | other backend  |
|    |           |   local proxy   |                  |                  | | (e.g. :5236)   |
|    v           +-----------------> (auth: prefix    +-----------------> +----------------+
|  local port    |  prepend token  |  magic-token)    |
+----------------+                 +------------------+
```

Pipeline per inbound connection: `ProtocolDetectHandler → AuthPrefixHandler → TcpRelayHandler`.

- **ProtocolDetectHandler** peeks at the first packet only (never consumes it):
  - First byte `0x16` (TLS Handshake) → **HTTPS/TLS**;
  - Known HTTP method prefix followed by a space (`GET `, `POST `, ... `PATCH `, `CONNECT `, `TRACE `) → **HTTP**;
  - 16 probe bytes received with no match → **OTHER**;
  - On probe timeout: if data was received, forward as **OTHER**; otherwise close the connection.
- **AuthPrefixHandler** validates/strips the fixed-length token for **OTHER** traffic only (HTTP/HTTPS never triggers auth). When auth is disabled, it passes everything through unchanged.
- **TcpRelayHandler** performs the transparent bidirectional relay and manages buffering/backpressure.

## Requirements

- JDK 1.8+
- Maven 3.x (for building)
- A server reachable from the public internet (to host the gateway)

## Build

```bash
mvn clean package
```

This produces an executable fat JAR at `target/tcp-gateway.jar`.

## Run

```bash
java -jar tcp-gateway.jar [config-path]
```

If no config path is given, the loader searches in this order:

1. `-D`/argument path → 2. environment variable `GATEWAY_CONFIG` → 3. `./gateway.yaml` in the working directory → 4. built-in default from the classpath.

Example:

```bash
java -jar tcp-gateway.jar gateway.yaml
```

## Docker Deployment

The project ships a ready-to-use [Dockerfile](Dockerfile) and [docker-compose.yaml](docker-compose.yaml). The containerized gateway is **configuration-driven, not image-driven**:

- **No `EXPOSE`** — the image does not fix any port. All port mapping happens at runtime with `docker run -p <host-port>:<container-port>` (or Compose `ports`).
- **No hardcoded IP/port** — the bundled [docker/gateway.yaml](docker/gateway.yaml) is only a placeholder with no IP/port values. Every runtime setting can be passed via `JQUICK_*` environment variables, which override the YAML. Precedence: **env var > YAML > code default**.
- **JRE base image** — multi-stage build: a Maven+JDK build stage produces the fat JAR, and an Eclipse Temurin **JRE** image is used as the runtime (smaller, no compiler).

### Environment variable overrides

| Env var | Overrides | Default |
|---|---|---|
| `JQUICK_LISTEN_HOST` | `gateway.listen.host` | `0.0.0.0` |
| `JQUICK_LISTEN_PORT` | `gateway.listen.port` | `8080` |
| `JQUICK_LISTEN_BACKLOG` | `gateway.listen.backlog` | `1024` |
| `JQUICK_LISTEN_SO_TIMEOUT` | `gateway.listen.so_timeout` | `5000` |
| `JQUICK_LISTEN_PROBE_TIMEOUT` | `gateway.listen.probe_timeout_ms` | `so_timeout` |
| `JQUICK_NGINX_HOST` / `JQUICK_NGINX_PORT` | `nginx.target.host` / `port` | `127.0.0.1` / `80` |
| `JQUICK_OTHER_HOST` / `JQUICK_OTHER_PORT` | `other.traffic.target.host` / `port` | `127.0.0.1` / `9000` |
| `JQUICK_AUTH_ENABLE` | `other.traffic.auth.enable` | `true` (only if an `auth` section exists) |
| `JQUICK_AUTH_TOKEN_PREFIX_LEN` | `other.traffic.auth.token-prefix-len` | `32` |
| `JQUICK_AUTH_TIMEOUT_MS` | `other.traffic.auth.timeout_ms` | `5000` |
| `JQUICK_AUTH_TOKENS` | `other.traffic.auth.valid-tokens` | — (comma-separated list) |
| `JQUICK_NETTY_BOSS_THREADS` / `JQUICK_NETTY_WORKER_THREADS` | `netty.boss.threads` / `netty.worker.threads` | `1` / `0` |
| `JQUICK_LEAK_DETECTION` | `netty.buffer.leak.detection` | `SIMPLE` |

### Build the image

```bash
docker build -t jquick-hub:1.0.0 .
```

### Run with `docker run`

**Reaching host services from the container: use `host.docker.internal`.** Inside a container, `127.0.0.1` refers to the container itself — so backend targets that run on the host machine (Nginx, databases, ...) must be addressed via `host.docker.internal`:

```bash
docker run -d --name jquick-hub --restart unless-stopped \
  -p 18080:18080 \
  -e JQUICK_LISTEN_PORT=18080 \
  -e JQUICK_NGINX_HOST=host.docker.internal -e JQUICK_NGINX_PORT=52000 \
  -e JQUICK_OTHER_HOST=host.docker.internal -e JQUICK_OTHER_PORT=5236 \
  -e JQUICK_AUTH_ENABLE=true -e JQUICK_AUTH_TOKEN_PREFIX_LEN=32 \
  -e JQUICK_AUTH_TOKENS=0123456789abcdef0123456789abcdef \
  jquick-hub:1.0.0
```

> `host.docker.internal` works out of the box on Windows/macOS Docker Desktop. On **Linux**, add `--add-host=host.docker.internal:host-gateway`.

**Alternative: mount your own YAML config** (env vars still override individual settings):

```bash
docker run -d --name jquick-hub \
  -p 18080:18080 \
  -v /path/to/gateway.yaml:/app/gateway.yaml:ro \
  jquick-hub:1.0.0
```

### Port mapping

Format: `-p <host-port>:<container-port>`.

- The **container port must equal `JQUICK_LISTEN_PORT`** — it is the port the JVM binds inside the container.
- The **host port is free to choose** — e.g. `-p 8080:18080` exposes the gateway on host port 8080; clients then connect to `<host>:8080`.
- Because the gateway routes multiple protocols through a **single** listening port, **one mapping is enough** to expose HTTP/HTTPS and plain TCP traffic at the same time. Add more `-p` lines only if you run multiple listener ports.
- There is no `EXPOSE` in the image on purpose: `EXPOSE` is only documentation and never actually publishes a port; the mapping is always decided at runtime.

### Run with docker compose

```yaml
services:
  jquick-hub:
    build:
      context: .
      dockerfile: Dockerfile
    image: jquick-hub:1.0.0
    container_name: jquick-hub
    restart: unless-stopped
    ports:
      - "18080:18080"
    environment:
      JQUICK_LISTEN_PORT: "18080"
      JQUICK_NGINX_HOST: "host.docker.internal"
      JQUICK_NGINX_PORT: "52000"
      JQUICK_OTHER_HOST: "host.docker.internal"
      JQUICK_OTHER_PORT: "5236"
      JQUICK_AUTH_ENABLE: "true"
      JQUICK_AUTH_TOKEN_PREFIX_LEN: "32"
      JQUICK_AUTH_TOKENS: "0123456789abcdef0123456789abcdef"
    # Linux only: reach the host via host.docker.internal
    # extra_hosts:
    #   - "host.docker.internal:host-gateway"
```

```bash
docker compose up -d --build
docker compose logs -f jquick-hub
```

### Verify

```bash
docker logs -f jquick-hub
```

A healthy startup prints the effective config (listen port, Nginx/other targets, auth settings). A successful relay logs `后端连接成功 <host>:<port>，开始透传` (backend connected, relaying). If a connection drops right after connecting, check the logs: `Connection refused` usually means the backend address is wrong or not reachable from inside the container — remember to use `host.docker.internal` for services running on the host.

## Configuration

All settings live in a single YAML file (`gateway.yaml`). An annotated example:

```yaml
gateway:
  listen:
    host: 0.0.0.0               # bind address (default: all interfaces)
    port: 18080                 # public listening port
    backlog: 1024              # TCP backlog (pending connection queue size)
    so_timeout: 5000           # connection timeout in ms (backend connect + probe wait upper bound)
    probe_timeout_ms: 5000     # probe wait upper bound (optional): max ms to wait for the first packet
                               # after timeout: if data was received, forward as plain TCP; if none, close
nginx:
  target:
    host: 127.0.0.1            # internal Nginx IP
    port: 52000                # Nginx port
other:
  traffic:
    target:
      host: 127.0.0.1          # forwarding IP for other traffic
      port: 5236               # forwarding port for other traffic
    auth:
      enable: true             # auth switch; on by default in production; false = full pass-through
      token-prefix-len: 32     # fixed token length in bytes; must match every token below
      timeout_ms: 5000         # auth timeout: close silently if no complete token arrives in time
      valid-tokens:            # list of valid tokens (each must be exactly token-prefix-len bytes)
        - "0123456789abcdef0123456789abcdef"   # example 32-byte token; replace with random values in production
netty:
  boss:
    threads: 1                 # boss threads (accepting new connections)
  worker:
    threads: 0                 # worker threads (I/O); 0 = auto (CPU cores * 2)
  buffer:
    leak:
      detection: SIMPLE        # leak detection level: SIMPLE | ADVANCED | PARANOID | DISABLED
```

### Configuration defaults

| Key | Default | Notes |
|---|---|---|
| `gateway.listen.host` | `0.0.0.0` | bind address; env override `JQUICK_LISTEN_HOST` |
| `gateway.listen.port` | `8080` | |
| `gateway.listen.backlog` | `1024` | must be a positive integer |
| `gateway.listen.so_timeout` | `5000` | ms |
| `gateway.listen.probe_timeout_ms` | `so_timeout` | falls back to `5000` if `so_timeout` ≤ 0 |
| `nginx.target.host` / `port` | `127.0.0.1` / `80` | |
| `other.traffic.target.host` / `port` | `127.0.0.1` / `9000` | |
| `other.traffic.auth.enable` | `true` | **only if an `auth` section exists**; legacy configs without `auth` keep auth disabled for backward compatibility |
| `other.traffic.auth.token-prefix-len` | `32` | bytes |
| `other.traffic.auth.timeout_ms` | `5000` | ms |
| `netty.boss.threads` | `1` | must be a positive integer |
| `netty.worker.threads` | `0` (auto) | `0` = CPU cores × 2 |
| `netty.buffer.leak.detection` | `SIMPLE` | |

> **Validation:** when auth is enabled, the program **refuses to start** if no valid tokens are configured, or if any token length differs from `token-prefix-len`. Port values must be within `1–65535`.

### Authentication how it works

Native TCP tools (Navicat, DBeaver, psql, ssh, ...) cannot send custom headers or modify their application-layer protocol. The gateway therefore uses a **prefix magic-token** scheme:

1. The client (e.g. `GatewayClient`) prepends a fixed-length token to the **first** business packet.
2. The gateway accumulates the first bytes, peeks (read-only) at the first `token-prefix-len` bytes and compares them against the valid token list.
3. On success: the token prefix is stripped; the remaining raw business data is forwarded as-is. Subsequent bytes pass through untouched.
4. On failure/timeout: the connection is **silently closed** (no response), avoiding information disclosure.

## Client (GatewayClient)

`client/GatewayClient.java` is a zero-dependency local mini-proxy that lets unmodified native tools pass the gateway's token auth:

```
DB tool ──connect──▶ local proxy (listens on local.ports) ──prepend token to first packet──▶ public gateway ──strip token──▶ internal DB
```

Connect your tools to the **local port** — no tool modification needed.

### Configuration (`client/client.properties`)

```properties
local.ports=15236                    # local listen ports, comma-separated (multiple allowed)
gw.host=127.0.0.1                    # gateway host
gw.port=18080                        # gateway port
token=0123456789abcdef0123456789abcdef   # auth token (must match a gateway valid-token)
```

### Run

Windows: double-click `start-client.bat` (auto-compiles on first run).

Or manually:

```bash
javac -encoding UTF-8 GatewayClient.java
java -Dfile.encoding=UTF-8 GatewayClient                                   # reads ./client.properties
java -Dfile.encoding=UTF-8 GatewayClient -config d:\xx\client.properties   # explicit config path
java -Dfile.encoding=UTF-8 GatewayClient -ports 5236 -host x.x.x.x -port 8080 -token xxxxxxxx
```

Command-line options (`-ports`, `-host`, `-port`, `-token`) override the properties file.

> **Security note:** the token is a secret. `client.properties` should be treated as sensitive (do not commit it to git; restrict file permissions). Logs only ever show a masked token.

## Project Structure

```
src/main/java/com/gateway/
├── JQuickGatewayServer.java          # main entry: bootstrap, thread groups, shutdown hook
├── config/
│   ├── JQuickConfigLoader.java       # YAML loading, env overrides, validation, defaults
│   └── JQuickGatewayConfig.java      # configuration model
└── handler/
    ├── JQuickProtocolDetectHandler.java   # first-packet protocol sniffing & routing
    ├── JQuickAuthPrefixHandler.java       # prefix magic-token auth for OTHER traffic
    └── JQuickTcpRelayHandler.java         # transparent bidirectional relay
client/
├── GatewayClient.java                # local mini-proxy client (zero third-party deps)
├── client.properties                 # client config
└── start-client.bat                  # Windows launcher
src/main/resources/gateway.yaml       # default server config
Dockerfile                            # multi-stage build: Maven+JDK → JRE runtime (no EXPOSE)
docker-compose.yaml                   # compose deployment example (host.docker.internal)
docker/gateway.yaml                   # image default config placeholder (no hardcoded IP/port)
pom.xml                               # Maven build (fat jar: tcp-gateway.jar)
```

## License

[Apache License 2.0](LICENSE)
