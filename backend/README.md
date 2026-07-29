# Vectro backend

## Requirements

- Python 3.13 and [uv](https://docs.astral.sh/uv/)
- OpenSSL for local Ed25519 JWT development keys
- Docker Desktop for the Docker workflow

## Native development

```bash
cd backend
uv sync
./scripts/generate-dev-jwt-keys.sh
DEBUG=false uv run alembic upgrade head
./scripts/run-dev.sh
```

The API is available at `http://127.0.0.1:8000/docs`. The native runner loads ignored files in
`.secrets/` and starts Uvicorn with reload; it never prints key contents.

## Docker development

From the repository root:

```bash
./backend/scripts/generate-dev-jwt-keys.sh
docker compose up --build
```

Compose runs PostgreSQL, a one-shot migration service, and the reload-enabled API. Development
keys are mounted read-only, never copied into the image. Use `docker compose down` to stop the
stack. `docker compose down -v` also deletes the local database volume and should be intentional.

Useful URLs: `http://127.0.0.1:8000/docs` and `http://127.0.0.1:8000/openapi.json`.
`GET /` returns `404` because Vectro has no root route; this is expected.

## Production-like Docker execution

Provide `SECRET_KEY`, `DATABASE_URL`, `JWT_PRIVATE_KEY`, and `JWT_PUBLIC_KEY` through your
platform secret manager, then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build
```

The production target has no source bind mount, no reload, no development dependencies, and runs
as a non-root user. It accepts direct PEM values or `JWT_PRIVATE_KEY_FILE` and
`JWT_PUBLIC_KEY_FILE` supplied by a mounted secret mechanism.

## Logs

`docker compose logs postgres` shows retained PostgreSQL logs. `--since=1m` limits output to the
last minute; `--tail=0 -f` follows only new lines. Integration tests deliberately exercise
database constraints, so historical PostgreSQL `ERROR` entries do not by themselves indicate a
current startup failure.
