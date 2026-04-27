# ntfy Publish Recipe (NEXUS)

Canonical publish path for `nexus-alerts`. Use this when you need to send an
alert from any service on NEXUS or from the LAN/Tailscale.

## Server

| Property | Value |
|---|---|
| Host | NEXUS (`192.168.1.20` LAN, `100.98.48.63` Tailscale) |
| Container | `ntfy` (`binwiederhier/ntfy:v2.11.0`) |
| Internal URL (docker `edge` net) | `http://ntfy:80` |
| LAN URL | `http://192.168.1.20:2586` |
| Tailscale URL | `http://100.98.48.63:2586` |
| Health endpoint | `GET /v1/health` -> `200 {"healthy":true}` |
| Compose file | `~/ntfy/docker-compose.yml` on NEXUS |

## Auth model

Topic-as-secret. `NTFY_ENABLE_LOGIN=false`,
`NTFY_AUTH_DEFAULT_ACCESS=read-write`. Anyone who knows the topic name can
publish or subscribe; anyone who does not, cannot. Treat the topic name like
a low-sensitivity shared secret. No password is required and **none should be
added** without first updating this doc.

## Canonical topic

`nexus-alerts` — single topic for Ron's NEXUS infra alerts (Cortex, Sentinel,
shared-brain, OpenClaw, etc.). Add new topics only for distinct audiences.

## Retention

`NTFY_CACHE_DURATION=12h` — messages survive subscriber disconnects for 12
hours, then are evicted. Don't rely on ntfy as durable storage; treat it as
push-only.

## Publish

### From inside the docker `edge` network (preferred for services)

```bash
curl -s -X POST \
  -H "Title: <short subject>" \
  -H "Priority: default" \
  -H "Tags: <comma,separated,tags>" \
  -d "<message body>" \
  http://ntfy/nexus-alerts
```

### From NEXUS host or LAN

```bash
curl -s -X POST \
  -H "Title: <short subject>" \
  -d "<message body>" \
  http://192.168.1.20:2586/nexus-alerts
```

### From Tailscale (remote dev box)

```bash
curl -s -X POST \
  -H "Title: <short subject>" \
  -d "<message body>" \
  http://100.98.48.63:2586/nexus-alerts
```

A successful publish returns HTTP 200 with a JSON envelope containing an
`id`, `time`, `expires`, `topic`, and the echoed `title`/`message`/`tags`.

## Headers used

| Header | Purpose |
|---|---|
| `Title` | Short subject line shown above the body. |
| `Priority` | `min` / `low` / `default` / `high` / `urgent`. |
| `Tags` | Comma-separated; some render as emoji on the ntfy UI. |
| `Click` | URL opened when the notification is tapped. |
| `Markdown: yes` | Render body as Markdown. |

## Subscribe (read-back)

One-shot poll for recent messages:

```bash
curl -s 'http://192.168.1.20:2586/nexus-alerts/json?poll=1&since=5m'
```

Long-poll stream (SSE):

```bash
curl -N 'http://192.168.1.20:2586/nexus-alerts/sse'
```

Mobile: install ntfy app, add server `http://192.168.1.20:2586` (LAN) or
`http://100.98.48.63:2586` (Tailscale), subscribe to topic `nexus-alerts`.

## Notes

- Phase A deployment: localhost + LAN + Tailscale only. No Cloudflare tunnel.
  Do not expose ntfy to the public internet without first switching to
  user/ACL auth (`NTFY_ENABLE_LOGIN=true` + `ntfy user add` + `ntfy access`).
- ntfy is an independent fallback sink to Signal-via-OpenClaw. If Signal
  delivery is broken, ntfy must still get the page out.
- Do not change the topic name without updating every publisher.
