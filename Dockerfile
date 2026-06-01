
# ─── BUILDER ─────────────────────────────────────────────
FROM python:3.10-slim AS builder

WORKDIR /build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=300 \
    PIP_RETRIES=10 \
    PIP_PROGRESS_BAR=off

RUN set -eux; \
        if [ -f /etc/apt/sources.list ]; then \
            sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list; \
        fi; \
        if ls /etc/apt/sources.list.d/*.sources >/dev/null 2>&1; then \
            sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/*.sources; \
        fi; \
        apt-get \
            -o Acquire::Retries=5 \
            -o Acquire::ForceIPv4=true \
            -o Acquire::http::Timeout=30 \
            -o Acquire::https::Timeout=30 \
            update; \
        apt-get install -y --no-install-recommends \
            build-essential \
            gcc \
            g++ \
            git; \
        rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
        set -eux; \
        python -m pip install --upgrade pip setuptools wheel; \
        awk '!/^[[:space:]]*($|#)/ { line=$0; sub(/[[:space:]]*#.*$/, "", line); if (line ~ /^[[:space:]]*pytest([[:space:]]*[<>=!~].*)?$/) next; if (line ~ /^[[:space:]]*pytest-asyncio([[:space:]]*[<>=!~].*)?$/) next; print $0 }' requirements.txt > /tmp/requirements.runtime.txt; \
        for attempt in 1 2 3; do \
            pip install --prefer-binary --timeout 600 --retries 20 -r /tmp/requirements.runtime.txt && break; \
            echo "pip install attempt ${attempt} failed"; \
            if [ "$attempt" -eq 3 ]; then \
                exit 1; \
            fi; \
            sleep $((attempt * 20)); \
        done

# ─── RUNTIME ─────────────────────────────────────────────
FROM python:3.10-slim

WORKDIR /app

RUN set -eux; \
        if [ -f /etc/apt/sources.list ]; then \
            sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list; \
        fi; \
        if ls /etc/apt/sources.list.d/*.sources >/dev/null 2>&1; then \
            sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/*.sources; \
        fi; \
        apt-get \
            -o Acquire::Retries=5 \
            -o Acquire::ForceIPv4=true \
            -o Acquire::http::Timeout=30 \
            -o Acquire::https::Timeout=30 \
            update; \
        apt-get install -y --no-install-recommends \
            libgl1 \
            libglib2.0-0 \
            libsm6 \
            libxext6 \
            libgomp1 \
            curl; \
        rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY app/ app/
COPY .env.example /app/.env.example

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
