# NetWall Flow Analyzer

NetWall Flow Analyzer ingests Clavister NetWall firewall connection logs (UDP syslog or file upload), reconstructs flows, and provides a web UI for zones, rules, and topology.

### Ingested log IDs

The backend accepts syslog records whose `id` (structured-data) starts with:

| ID prefix | Type   | Use |
|-----------|--------|-----|
| `0060` / `60` | **CONN** | Connection logs. Used to build events and flows: zones, rules, topology, and traffic views. (InControl may send e.g. `600004`.) |
| `0890` / `89` | **DEVICE** | Device identification logs. Used to upsert device inventory (MAC, IP, vendor, type, hostname) and to sync endpoint metadata. (InControl may send e.g. `890001`.) |

Records with any other `id` are stored as raw logs but not processed into events or device records.

**Clavister NetWall:** When sending logs from a NetWall firewall to this analyzer, set **RFC5424 compliance** on the syslog configuration so that messages use the expected format (e.g. structured data with `id=...`) and can be parsed correctly.

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

## License

MIT. See [LICENSE](LICENSE).
