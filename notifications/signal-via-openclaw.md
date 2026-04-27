# Signal Notifications via OpenClaw (NEXUS)

Canonical path for routing Signal alerts from any service on NEXUS through
OpenClaw to a Signal recipient. Use this when an alert needs to land on a
phone (DM), versus ntfy which is the cheap broadcast channel.

## Routing flow

```
shared-brain SignalDaemon
  POST /tools/invoke (Bearer token)
  body: { tool: "message", args: { action: "send",
                                   to, message,
                                   channel: "signal",
                                   accountId } }
        |
        v
openclaw-openclaw-gateway-1 :18789
  authorizes Bearer (gateway.auth.mode = "token")
  resolves channels.signal.accounts[accountId]
        |
        v
sendMessageSignal -> signalRpcRequest
  if account.transport == "rest" -> POST http://signal-api:8080/v2/send
  if account.transport == "json-rpc" (default) ->
                                      POST {accountBaseUrl}/api/v1/rpc
        |
        v
signal-api (bbernhard/signal-cli-rest-api in json-rpc mode)
  -> signal-cli daemon -> Signal Foundation servers
        |
        v
recipient phone (Signal app)
```

## Components on NEXUS

| Component | Container | Internal URL | Notes |
|---|---|---|---|
| OpenClaw gateway | `openclaw-openclaw-gateway-1` | `http://openclaw-openclaw-gateway-1:18789` | bind-mounts `~/.openclaw/` for config |
| signal-api | `signal-api` | `http://signal-api:8080` | bbernhard/signal-cli-rest-api 0.98, mode=json-rpc, on `edge` network |
| shared-brain | `shared-brain-mcp` | `http://shared-brain-mcp:3100` | publishes `OPENCLAW_GATEWAY_TOKEN` env var, calls SignalDaemon for Cortex alerts |

## Auth model

Bearer token between shared-brain and OpenClaw. Single shared token in the
env var `OPENCLAW_GATEWAY_TOKEN`, present in both containers (verify with
`docker exec <container> printenv OPENCLAW_GATEWAY_TOKEN`). The token is
ALSO mirrored into `~/.openclaw/openclaw.json` at `gateway.auth.token`.

`gateway.auth.mode` MUST be `"token"`. Other modes:
- `"trusted-proxy"` — validates `x-forwarded-*` headers from a trusted proxy
  (Tailscale Serve, Traefik with auth header). Ignores Bearer tokens. Only
  use when shared-brain reaches OpenClaw via Tailscale ingress, not direct.
  This was the broken setup until 2026-04-27.
- `"password"` — basic-auth; not used here.
- `"none"` — disabled; never use in production.

OpenClaw → signal-api has no auth (loopback inside docker `edge` network).
signal-api → Signal Foundation uses each account's registered identity
keys (managed by signal-cli's account store at
`/home/.local/share/signal-cli/data/`).

## Configuring an account

Per-account config in `~/.openclaw/openclaw.json` under `channels.signal.accounts`:

```json
{
  "channels": {
    "signal": {
      "enabled": true,
      "accounts": {
        "primary": {
          "account": "+17408197558",
          "transport": "rest",
          "httpUrl": "http://signal-api:8080",
          "autoStart": false,
          "dmPolicy": "disabled"
        }
      }
    }
  }
}
```

Required fields:
- `account` — E.164 sender number, MUST be registered in signal-api (check
  with `curl http://signal-api:8080/v1/accounts`).
- `transport` — `"rest"` for shared signal-cli-rest-api containers,
  `"json-rpc"` for a local signal-cli daemon.
- `httpUrl` — base URL of the signal backend. For REST transport, this
  points at signal-api. For JSON-RPC, it points at a local
  `signal-cli daemon --http :PORT`.
- `autoStart` — set `false` when using REST transport (no local daemon to
  spawn). When `true` (the default for the JSON-RPC transport), OpenClaw
  spawns `signal-cli daemon` from `cliPath`.

Recipient targeting in the `to` field:
- `+E.164` — direct DM to a number
- `signal:+E.164` — same, with explicit channel prefix
- `signal:group:<base64-id>` — group message
- `signal:username:<handle>` or `u:<handle>` — username addressing
  (NOT supported by the REST transport; use a number instead)

## Diagnostic curl recipes

### 1. Bypass everything — direct to signal-api

```bash
docker exec shared-brain-mcp sh -c '
  curl -sS -X POST http://signal-api:8080/v2/send \
    -H "Content-Type: application/json" \
    -d "{\"number\":\"+17408197558\",
         \"recipients\":[\"+17408197558\"],
         \"message\":\"direct test\"}" \
    -w "\nHTTP %{http_code}\n"
'
# Expect: 201 with {"timestamp":"<unix-ms>"}
```

If this fails, the issue is at signal-cli / Signal account level, NOT
OpenClaw or shared-brain.

### 2. Through OpenClaw — what shared-brain actually does

```bash
docker exec shared-brain-mcp sh -c '
  printf "%s" "{\"tool\":\"message\",\"args\":{
    \"action\":\"send\",
    \"to\":\"+17408197558\",
    \"message\":\"openclaw plumbing test\",
    \"channel\":\"signal\",
    \"accountId\":\"primary\"
  }}" | curl -sS -X POST \
    http://openclaw-openclaw-gateway-1:18789/tools/invoke \
    -H "Authorization: Bearer $OPENCLAW_GATEWAY_TOKEN" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    -w "\nHTTP %{http_code}\n"
'
# Expect: 200 with {"ok":true,"result":{"details":{"result":{"messageId":"..."}}}}
```

Failure modes:
- HTTP 401 with `token_mismatch` or `trusted_proxy_*` reason → check
  `gateway.auth.mode` is `"token"` and the env var matches
  `gateway.auth.token`.
- HTTP 500 `Signal REST send failed: HTTP 400` → signal-api returned 400.
  The sending account may be in a half-registered state; try recipe (1)
  with the same `number` to confirm.
- HTTP 500 `Signal REST transport requires account in params` → the account
  config is missing the `account` E.164 field, or accountId routes to an
  account that has none.

### 3. Watch shared-brain side

```bash
docker logs shared-brain-mcp --since 5m 2>&1 | grep SignalClient
```

`[SignalClient] Send failed` or `[SignalClient] Gateway not reachable` are
the two failure breadcrumbs. If you see neither and Cortex still doesn't
deliver, the alert isn't reaching SignalDaemon at all (check
`AlertManager` and the cortex caller).

## Recovery checklist when alerts go silent

1. `docker ps | grep -E "openclaw|signal-api|shared-brain"` — all three up?
2. `curl http://signal-api:8080/v1/accounts` — sending account in the list?
3. Diagnostic recipe (1) — does signal-api itself work?
4. Diagnostic recipe (2) — does the OpenClaw path work?
5. `docker logs openclaw-openclaw-gateway-1 --tail 100 | grep -iE "auth|signal"`
   — auth failures, REST failures, daemon spawn errors?
6. shared-brain log scan (recipe 3).

## See also

- [ntfy-publish.md](./ntfy-publish.md) — parallel broadcast channel
- OpenClaw source: `src/signal/{send,client,rpc-context}.ts`,
  `src/config/zod-schema.providers-core.ts` (SignalAccountSchemaBase)
