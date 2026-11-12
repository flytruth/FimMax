# syntax=docker/dockerfile:1.7
#
# Multi-stage build for wazuh-fim-telegram.
#
# stage 1 (builder): installs build deps, builds wheels for runtime deps.
# stage 2 (runtime): slim image with only the wheels + bash entrypoints.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random

WORKDIR /build

# Build deps for any C-extension wheels (pydantic-core, etc.).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY scripts/ ./scripts/

# Build wheels into /wheels so the runtime stage can install them cheaply.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip wheel setuptools \
    && pip wheel --no-cache-dir --wheel-dir=/wheels .


FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PYTHONPATH=/app/src \
    PIP_NO_CACHE_DIR=1

# bash + ca-certs + sqlite3 (for the healthcheck) + tini (PID 1 signal handling).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        sqlite3 \
        tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the wheels we built.
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

# Application files.
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY config/ ./config/

# Make scripts executable + create the state dir (writable by the container).
RUN chmod +x scripts/*.sh \
    && mkdir -p /var/lib/wazuh-fim-telegram \
    && ln -sf /app/scripts/fim-watcher.sh /usr/local/bin/fim-watcher

# Non-root user. UID/GID 1000 is conventional and matches most CI runners.
RUN groupadd --system --gid 1000 wazuh-fim \
    && useradd --system --uid 1000 --gid wazuh-fim \
       --home-dir /app --shell /usr/sbin/nologin wazuh-fim \
    && chown -R wazuh-fim:wazuh-fim /app /var/lib/wazuh-fim-telegram

USER wazuh-fim
VOLUME ["/var/lib/wazuh-fim-telegram"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD /app/scripts/healthcheck.sh || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/app/scripts/fim-watcher.sh"]
CMD ["run"]
