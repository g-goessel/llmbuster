# syntax=docker/dockerfile:1.7

# ---- Stage 1: build venv with deps + project installed --------------------
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.26 /uv /bin/uv

WORKDIR /app

ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

# Install deps first (cached layer).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source and install the project (non-editable) into the venv.
COPY llmbuster/ ./llmbuster/
COPY README.md LICENSE ./
RUN uv pip install --no-deps --no-cache .

# ---- Stage 2: minimal runtime --------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv

WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["llmbuster"]
CMD ["--help"]
