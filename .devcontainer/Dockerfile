FROM ghcr.io/astral-sh/uv:latest AS uv
FROM mcr.microsoft.com/devcontainers/python:3.12

COPY --from=uv /uv /uvx /bin/
