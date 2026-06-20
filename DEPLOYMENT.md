# VulnTriage — Deployment for Penetration Testers (Kali Linux)

Three ways to run the AI-Assisted Vulnerability Triage System on a pentest box:

1. **Desktop app** — a native window (like ZAP) launched from the Kali
   applications menu. SQLite, no browser, no terminal. Best for interactive use.
2. **Docker Compose** — the full web app (UI + API + ML + database) in one command.
3. **CLI tool (`vulntriage`)** — a terminal command that runs the whole triage
   pipeline on a scanner file and drops a PDF report. No browser, no services.

All three use the *same* engines — the desktop app and CLI are just different
front doors to the pipeline the web UI drives.

---

## 1. Desktop app (native window, recommended for interactive use)

A real application window powered by `pywebview` (GTK/WebKit), serving your
existing React UI from an embedded Flask server backed by SQLite. Double-click
the menu entry and the GUI opens — no `docker`, no browser, no terminal.

### Build the frontend first (on your dev machine)
The desktop app serves the *compiled* UI, so make sure `frontend/dist` exists
and is included in what you copy to Kali:
```bash
cd frontend && npm run build      # produces frontend/dist
```
(If you transferred with the clean-zip command, make sure it does **not**
exclude `dist`.)

### Install on Kali (one command)
```bash
cd ~/FYP
chmod +x install-kali-app.sh
./install-kali-app.sh
```
This installs the GTK/WebKit system packages pywebview needs, creates a
virtualenv (`--system-site-packages` so it can see them), installs all Python
deps, builds the frontend if needed, and registers **VulnTriage** in your
applications menu.

### Launch
- Search **VulnTriage** in the Kali applications menu, **or**
- Run `~/FYP/bin/vulntriage-app`

Default login: **admin / admin**. The database lives at
`~/.local/share/vulntriage/vulntriage.db` and persists across launches.

### Manual setup (if you'd rather not use the installer)
```bash
sudo apt install -y python3-venv python3-gi python3-gi-cairo \
    gir1.2-gtk-3.0 gir1.2-webkit2-4.1
cd ~/FYP/backend
python3 -m venv .venv --system-site-packages    # MUST be --system-site-packages
source .venv/bin/activate
pip install -r requirements.txt -r requirements-desktop.txt
cd ~/FYP && python backend/desktop_app.py
```

> **Why `--system-site-packages`?** pywebview's Linux backend uses the system
> GTK/WebKit2 bindings (`gi`), which can't be installed with pip. The venv needs
> to see them. If you used `gir1.2-webkit2-4.0` (older Kali), pywebview still
> auto-detects it.

---

## 2. Docker Compose (full web app)

### Requirements
```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
```

### Run
From the project root (the folder containing `docker-compose.yml`):
```bash
docker compose up --build
```
Then open **http://localhost:5000** and log in with **admin / admin**.

That single command:
- builds the React UI into static files,
- starts PostgreSQL in a container (you never install or manage it),
- creates the schema and seeds the `admin` user,
- serves the UI + API from one port (5000),
- ships with the trained ML model already inside the image.

### Configuration (optional)
Override any of these via environment or a `.env` file next to `docker-compose.yml`:

| Variable          | Default                  | Purpose                          |
|-------------------|--------------------------|----------------------------------|
| `APP_PORT`        | `5000`                   | Host port to expose              |
| `ADMIN_USERNAME`  | `admin`                  | Seeded web-UI login              |
| `ADMIN_PASSWORD`  | `admin`                  | Seeded web-UI password           |
| `SECRET_KEY`      | `change-me-in-production`| Flask session secret             |
| `JWT_SECRET_KEY`  | `change-me-jwt-…`        | JWT signing secret               |
| `NVD_API_KEY`     | *(empty)*                | Faster NVD enrichment if set     |
| `POSTGRES_PASSWORD`| `password`              | Database password                |

Example `.env`:
```env
ADMIN_PASSWORD=supersecret
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
NVD_API_KEY=your-nvd-key
```

### Lifecycle
```bash
docker compose up -d --build     # run in the background
docker compose logs -f app       # follow logs
docker compose down              # stop (keeps data)
docker compose down -v           # stop and wipe the database/uploads
```
Uploaded scans, generated reports, and the database persist in named volumes
(`uploads`, `reports`, `pgdata`) across restarts.

---

## 3. CLI tool (`vulntriage`)

Built for the terminal workflow: scan → triage → PDF, in one line. Defaults to
a single-file SQLite database (`./vulntriage.db`) so it runs **standalone** with
no PostgreSQL.

### Install (Kali / Debian)
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd ..

# optional: put `vulntriage` on your PATH
sudo ln -s "$(pwd)/bin/vulntriage" /usr/local/bin/vulntriage
```
If you used a venv, point the launcher at it:
```bash
export VULNTRIAGE_PYTHON="$(pwd)/backend/.venv/bin/python"
```

### Usage
```bash
# Triage a ZAP XML report (scanner auto-detected from the filename)
vulntriage scan zap-report.xml

# Be explicit about the scanner, run live PoC checks, choose the PDF path
vulntriage scan results.xml -s zap --poc -o ./report.pdf

# Nuclei / Nessus
vulntriage scan findings.json -s nuclei
vulntriage scan scan.nessus  -s nessus

# Inspect the active DB + ML model
vulntriage info
```

Without the launcher symlink, run it directly (works on any OS, incl. Windows):
```bash
python backend/cli.py scan results.xml -s zap --poc
```

### Options
| Flag                | Description                                                        |
|---------------------|--------------------------------------------------------------------|
| `-s, --scanner`     | `zap` \| `nuclei` \| `nessus` (auto-detected if omitted)           |
| `--poc / --no-poc`  | Run live, non-destructive PoC validation against target URLs       |
| `-o, --output`      | Where to write the PDF (default: `backend/reports_output/`)        |
| `--db`              | Database URL (default: `./vulntriage.db` SQLite)                   |
| `--top`             | How many findings to list in the terminal summary (default 10)     |
| `-q, --quiet`       | Suppress per-step progress output                                  |

### Sharing one database with the web app
Point the CLI at the same Postgres the Docker stack uses so CLI scans show up
in the web UI:
```bash
vulntriage scan results.xml \
  --db postgresql://postgres:password@localhost:5432/vuln_triage_db
```

> **PoC validation makes live HTTP requests** to the URLs in the scan report.
> Only use `--poc` against targets you are authorised to test.

---

## Notes

- **Python version:** the Docker image pins **Python 3.12** (the pinned
  numpy/scikit-learn/pandas have prebuilt wheels for it, so the image builds
  with no compiler). Local dev on the host uses 3.14; the app code is
  compatible with both.
- **ML model:** `ml_data/models/random_forest.pkl` is baked into the image and
  loaded by both the web app and the CLI. Retrain locally with the training
  script and rebuild the image to update it.
- **Offline use:** NVD enrichment needs network access; if it's unavailable the
  pipeline logs a warning and continues (CVSS-based severity is still used).
