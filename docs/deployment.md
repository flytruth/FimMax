# Deployment

## Prerequisites

- A Wazuh manager with the REST API enabled. Default port is 55000; verify
  with `curl -k -u wazuh:wazuh https://<manager>:55000/`.
- API credentials with at least `read` permission on `events` (or
  `syscheck:read` if you use `WAZUH_SOURCE=syscheck`).
- A Telegram bot token (from [@BotFather](https://t.me/BotFather)) and the
  numeric ID of the chat/channel you want alerts pushed to.

## Docker Compose (recommended)

```bash
git clone https://github.com/your-org/wazuh-fim-telegram.git
cd wazuh-fim-telegram
cp .env.example .env
cp config/rules.example.yaml config/rules.yaml

# Edit both files:
$EDITOR .env
$EDITOR config/rules.yaml

docker compose up -d --build
docker compose logs -f
```

The compose file:

- Mounts a named volume `fim-state` at `/var/lib/wazuh-fim-telegram` so the
  SQLite state (last-seen cursor, mutes, recent events) survives container
  restarts and image upgrades.
- Mounts `./config/rules.yaml` read-only at `/app/config/rules.yaml`. Edit
  the file on the host and `docker compose restart` to pick up changes.
- Sets CPU/memory limits (1 CPU / 256 MB) and reservations (0.1 CPU / 64 MB).
  Typical idle usage is ~30 MB.
- Runs as non-root user `wazuh-fim` (UID 1000).

### Upgrading

```bash
git pull
docker compose build --no-cache
docker compose up -d
```

The SQLite schema is forward-compatible (additive `CREATE TABLE IF NOT
EXISTS`); no migration scripts are needed between minor versions.

### Viewing logs

Logs are JSON lines on stdout:

```bash
docker compose logs -f --tail=100 wazuh-fim-telegram
```

For prettier output locally, set `LOG_FORMAT=console` in `.env` and restart.

## systemd (bare metal / Wazuh manager host)

If you'd rather run on the Wazuh manager itself (or any Linux box with
Python 3.10+):

```bash
# Install
sudo mkdir -p /etc/wazuh-fim-telegram
sudo pip install --break-system-packages /path/to/wazuh-fim-telegram
sudo cp .env.example /etc/wazuh-fim-telegram/.env
sudo cp config/rules.example.yaml /etc/wazuh-fim-telegram/rules.yaml
sudo $EDITOR /etc/wazuh-fim-telegram/.env
sudo $EDITOR /etc/wazuh-fim-telegram/rules.yaml
```

Create `/etc/systemd/system/wazuh-fim-telegram.service`:

```ini
[Unit]
Description=Wazuh FIM → Telegram bridge
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wazuh-fim
Group=wazuh-fim
EnvironmentFile=/etc/wazuh-fim-telegram/.env
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/usr/lib/python3/site-packages
Environment=STATE_PATH=/var/lib/wazuh-fim-telegram/state.sqlite
Environment=RULES_PATH=/etc/wazuh-fim-telegram/rules.yaml
ExecStart=/usr/local/bin/fim-watcher run
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/wazuh-fim-telegram
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
CapabilityBoundingSet=
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-fim
sudo mkdir -p /var/lib/wazuh-fim-telegram
sudo chown wazuh-fim:wazuh-fim /var/lib/wazuh-fim-telegram /etc/wazuh-fim-telegram
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-fim-telegram
journalctl -u wazuh-fim-telegram -f
```

## First-run smoke test

After deployment, send a synthetic alert to verify the Telegram pipeline
end-to-end (without involving Wazuh):

```bash
# Docker:
docker compose exec wazuh-fim-telegram /app/scripts/send-test-alert.sh

# Bare metal:
sudo -u wazuh-fim fim-watcher send-test
```

You should receive a `🔴 FIM alert [HIGH]` message in your Telegram chat.

Then verify the Wazuh side:

```bash
# Docker:
docker compose exec wazuh-fim-telegram fim-watcher validate-config

# Then, in Telegram:
/status
```

`/status` should show non-zero `cycles` within `WAZUH_POLL_INTERVAL_SEC`
seconds. If `events_seen` stays at 0 after a few minutes, check the
[Troubleshooting](../README.md#troubleshooting) section of the README.

## Health check

The Docker image ships with `scripts/healthcheck.sh` as its `HEALTHCHECK`.
It checks that the SQLite state DB was written to recently (within 5× the
poll interval). Inspect with:

```bash
docker inspect --format '{{json .State.Health}}' wazuh-fim-telegram | jq
```

For systemd, a similar probe can be wired into a monitoring system of your
choice — point it at `/var/lib/wazuh-fim-telegram/state.sqlite` and run the
same script, or `systemctl is-active wazuh-fim-telegram`.

## Backups

The only stateful artefact is the SQLite file at `STATE_PATH` (default
`/var/lib/wazuh-fim-telegram/state.sqlite`). Back it up with `sqlite3
.dump` or by copying the file (after `docker compose stop` or while the bot
is idle, to avoid WAL contention).

Loss of this file means: the bot will re-process events since the last
Wazuh-side retention — typically a few hours, since the `/events` endpoint
only returns recent items. Mutes are also lost; users will need to re-mute.

## Tuning

| Goal                          | Knob                                  |
| ----------------------------- | ------------------------------------- |
| Lower alert latency           | `WAZUH_POLL_INTERVAL_SEC=10`          |
| Higher throughput (busy Wazuh)| `WAZUH_PAGE_SIZE=500`, `WAZUH_MAX_EVENTS_PER_CYCLE=2000` |
| Reduce noise                  | Edit `config/rules.yaml` (`action: drop` / `mute`) |
| Daily digest at 8am local     | `DIGEST_CRON=0 8 * * *`, `DIGEST_TIMEZONE=Europe/Berlin` |
| Debug a single event          | `LOG_LEVEL=DEBUG`, `LOG_FORMAT=console` |

## Connecting to Wazuh indexer (optional, future)

If you'd rather query the Wazuh Indexer (OpenSearch) directly instead of the
Wazuh API — useful for older Wazuh versions or for richer queries — set:

```
WAZUH_SOURCE=events
WAZUH_API_URL=https://wazuh-indexer:9200
WAZUH_API_USER=admin
WAZUH_API_PASSWORD=admin
WAZUH_AUTH_STRATEGY=basic
```

…and ensure your index has `rule.groups: syscheck` documents. The client's
`/events` endpoint maps cleanly to OpenSearch's `_search` with a query
filter. (Note: this is a future improvement; currently the client uses the
Wazuh manager API at port 55000, not the indexer at 9200.)
