# Multi-stage: build frontend, then run backend with static assets.
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY backend/ ./backend/
COPY --from=frontend /build/dist ./backend/frontend_dist
WORKDIR /app/backend
RUN pip install --no-cache-dir -e .

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV PYTHONUNBUFFERED=1
EXPOSE 8080 5514
ENTRYPOINT ["/entrypoint.sh"]
