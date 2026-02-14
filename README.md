# NetWall Flow Analyzer

NetWall CONN Flow Analyzer ingests firewall connection logs (UDP syslog or file upload), reconstructs flows, and provides a web UI for zones, rules, and topology.

## Architecture

- **Backend** (Python, FastAPI): HTTP API, UDP syslog receiver, file-upload ingest, flow aggregation, PostgreSQL or SQLite storage. Optional static serving of the built frontend.
- **Frontend** (Vite + React): Dashboard, zone/rule views, flow graph. Proxies `/api` to the backend in development.
- **Database**: PostgreSQL (recommended) or SQLite. Schema is managed via SQLAlchemy models and optional Alembic migrations.

## Quick start

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[test]"

# Run (default: PostgreSQL at localhost/netwall; override with --database-url for SQLite)
python -m app --web-port 8080
# Or with SQLite and serve frontend:
python -m app --database-url "sqlite:///./netwall.db" --serve-frontend --frontend-dir ../frontend/dist
```

### Frontend (development)

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 (Vite dev server proxies `/api` to the backend; run backend on the port configured in `vite.config.ts`, e.g. 18080, or adjust the proxy target).

### One-shot (backend serves frontend)

```bash
cd frontend && npm run build
cd ../backend && python -m app --serve-frontend --frontend-dir ../frontend/dist
```

Then open http://localhost:8080 (or the port you set with `--web-port`).

### Docker (production)

Build and run with Docker Compose (backend + PostgreSQL):

```bash
docker compose up -d
```

- App: http://localhost:8080  
- UDP syslog: port 5514  
- Database URL is set via `DATABASE_URL` (default in Compose: `postgresql+psycopg://postgres:postgres@db:5432/netwall`).

Standalone image (use an external database or SQLite):

```bash
docker build -t netwall-flow-analyzer .
docker run -p 8080:8080 -p 5514:5514/udp -e DATABASE_URL="sqlite:///./data/netwall.db" netwall-flow-analyzer
```

## Configuration

The backend is configured via **command-line arguments** (and optionally environment variables if you load them before invoking the app). Main options:

| Option | Default | Description |
|--------|---------|-------------|
| `--web-host` | `0.0.0.0` | HTTP bind address |
| `--web-port` | `8080` | HTTP port |
| `--syslog-host` | `0.0.0.0` | UDP syslog bind address |
| `--syslog-port` | `5514` | UDP syslog port |
| `--database-url` | `postgresql+psycopg://localhost/netwall` | SQLAlchemy URL (PostgreSQL or SQLite) |
| `--serve-frontend` | off | Serve built frontend from backend |
| `--frontend-dir` | `./frontend/dist` | Path to built frontend assets |
| `--log-level` | `info` | Logging level |
| `--year-mode` | `current` | Year inference for syslog timestamps |
| `--classification-precedence` | `zone_first` | Zone vs interface precedence for recv/dest |

See `.env.example` for suggested environment variable names if you use a process manager or Docker.

## Screenshots

_Placeholder: add screenshots of the dashboard, zone view, and flow graph here._

## What not to commit

Do **not** commit secrets, local runtime, or build artifacts. The root `.gitignore` excludes:

- `.env` (secrets)
- `backend/.venv/`, `frontend/node_modules/`
- `*.db`, `*.db-shm`, `*.db-wal`
- `backend/uploads/`, `frontend/dist/`
- `backend/.pytest_cache/`, `backend/*.egg-info/`
- IDE/OS files (e.g. `.idea/`, `.DS_Store`)

## License

MIT. See [LICENSE](LICENSE).
