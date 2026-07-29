FROM ghcr.io/astral-sh/uv:0.10.8 AS uv

FROM python:3.13-slim AS base
COPY --from=uv /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

FROM base AS development
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --group dev --no-install-project
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts/docker-entrypoint.sh /usr/local/bin/vectro-entrypoint
RUN chmod 755 /usr/local/bin/vectro-entrypoint
ENTRYPOINT ["vectro-entrypoint"]

FROM base AS production
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts/docker-entrypoint.sh /usr/local/bin/vectro-entrypoint
RUN useradd --create-home --uid 10001 vectro \
    && chown -R vectro:vectro /app /opt/venv \
    && chmod 755 /usr/local/bin/vectro-entrypoint
USER vectro
EXPOSE 8000
ENTRYPOINT ["vectro-entrypoint"]
CMD ["sh", "-c", "uv run --no-sync uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
