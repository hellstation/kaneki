# kaneki — Telegram OSINT toolbox

![Bot Interface](assets/image.png)

Telegram bot for ID lookup and OSINT-style checks (username, phone, email, Dutch vehicle plates, domain/IP HTML reports).

## Quick start

```bash
cp .env.example .env
# Set BOT_TOKEN and optionally ALLOWED_USER_IDS

pip install -r requirements.txt
python -m kaneki.bot
```

Docker:

```bash
cp .env.example .env
docker compose up -d --build
```

Optional Redis (FSM + rate limits across restarts):

```bash
# .env: REDIS_URL=redis://redis:6379/0
docker compose --profile redis up -d --build
```

## Access control

Set `ALLOWED_USER_IDS` to a comma-separated list of Telegram numeric user IDs. When empty, the bot is open to everyone who can message it.

Use **Profile** in the bot to see your ID.

## Rate limits and load

Per-user cooldowns (seconds) are configured in `.env` — see `RATE_LIMIT_*` and `DOMAIN_RATE_LIMIT_SECONDS`.

`OSINT_MAX_CONCURRENT` caps how many heavy scans run at once inside one bot process.

## GHunt (email / Google)

Mount GHunt credentials into the container (see `docker-compose.yml` volume for `~/.malfrats/ghunt`).

## Ethics and legal use

Use only on targets you are allowed to investigate. The bot aggregates public and third-party data; you are responsible for compliance with local law and platform terms.

## Project layout

- `kaneki/` — bot code (handlers, OSINT modules, domain security analyzer)
- `assets/` — banner image for Telegram UI
- `tests/` — unit tests (`python -m unittest discover -s tests`)

## CI

GitHub Actions runs unit tests, `compileall`, Docker build, and deploys `main` to VPS when secrets are configured.
