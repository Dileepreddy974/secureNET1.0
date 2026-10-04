FROM node:22-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SECURENET_STATIC_DIR=/app/frontend/dist
WORKDIR /app
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir . \
    && groupadd --gid 10001 lab \
    && useradd --uid 10001 --gid lab --no-create-home lab \
    && mkdir -p /app/.data /keys/sender /keys/receiver /secrets /account/data /account/storage /account/secret \
    && chown -R lab:lab /app/.data /keys /secrets /account \
    && chmod 700 /app/.data /keys/sender /keys/receiver /secrets /account/data /account/storage /account/secret
COPY --from=frontend /build/dist ./frontend/dist
USER lab
EXPOSE 8000
CMD ["securenet", "serve", "--host", "0.0.0.0"]
