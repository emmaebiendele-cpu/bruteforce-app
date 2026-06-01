# BruteShield 🛡️
### ML-Powered Brute Force Detection System

A production-grade authentication security system that detects, classifies, and blocks login attacks in real time using a hybrid rule-based + machine learning pipeline.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLIENTS                             │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTP
┌────────────────────────────▼────────────────────────────────┐
│              FastAPI Application (Python 3.12)              │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  IPBlockMiddleware  ← PostgreSQL BlockedIP table      │  │
│  │  (runs on every request, returns 403 if blocked)      │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │  Auth Routes │  │ Admin Routes │  │   Static/HTML     │  │
│  │  /api/auth/  │  │ /api/admin/  │  │   Jinja2 pages    │  │
│  └──────┬───────┘  └──────────────┘  └───────────────────┘  │
│         │                                                   │
│  ┌──────▼──────────────────────────────────────────────┐    │
│  │           Authentication Pipeline                   │    │
│  │                                                     │    │
│  │  1. Credential verification                         │    │
│  │  2. Rule-based classifier                           │    │
│  │     ├─ Brute Force   (1 IP → 1 account)            │    │
│  │     ├─ Spray         (1 IP → many accounts)        │    │
│  │     └─ Stuffing      (many IPs → many accounts)    │    │
│  │  3. ML inference (Random Forest + Isolation Forest) │    │
│  │  4. Auto-block if threshold exceeded                │    │
│  │  5. Write to login_logs                             │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                  PostgreSQL 16                               │
│  Tables: users │ login_logs │ blocked_ips │                  │
│           active_sessions │ ml_anomalies                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer      | Technology |
|------------|-----------|
| Backend    | Python 3.12, FastAPI, SQLAlchemy 2.x (async) |
| Frontend   | Vanilla JS, Jinja2 templates, custom CSS |
| Database   | PostgreSQL 16 (asyncpg driver) |
| Auth       | JWT (python-jose), bcrypt (passlib) |
| ML         | scikit-learn (RandomForest + IsolationForest), joblib, pandas |
| Packaging  | Docker, Docker Compose |

---

## Quick Start

### Option A – Docker Compose (recommended)

```bash
git clone <repo>
cd bruteforce_detection
docker-compose up --build
```

Visit http://localhost:8000

### Option B – Local Python

```bash
# 1. Create & activate a virtualenv
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
cp .env.example .env
# Edit .env – set DATABASE_URL to your local Postgres

# 4. Seed the database & train the initial model
python scripts/seed.py

# 5. Run the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## Default Credentials (after seeding)

| Role  | Username   | Password     |
|-------|-----------|--------------|
| Admin | `admin`    | `Admin1234!` |
| User  | `testuser` | `Test1234!`  |

---

## Pages

| URL          | Description |
|--------------|-------------|
| `/`          | Login page |
| `/register`  | Account registration |
| `/dashboard` | User dashboard (post-login) |
| `/admin`     | Admin dashboard |
| `/docs`      | FastAPI Swagger UI |

---

## API Reference

### Authentication

| Method | Endpoint              | Description |
|--------|-----------------------|-------------|
| POST   | `/api/auth/register`  | Create account |
| POST   | `/api/auth/login`     | Obtain JWT token |
| POST   | `/api/auth/logout`    | Invalidate session |
| GET    | `/api/auth/me`        | Current user info |

### Admin (requires admin JWT)

| Method | Endpoint                       | Description |
|--------|-------------------------------|-------------|
| GET    | `/api/admin/users/active`     | Live active sessions |
| GET    | `/api/admin/logs`             | Paginated login log table |
| GET    | `/api/admin/logs/stats`       | Attack type breakdown |
| GET    | `/api/admin/blocked-ips`      | All blocked IPs |
| POST   | `/api/admin/blocked-ips`      | Manually block an IP |
| DELETE | `/api/admin/blocked-ips/{ip}` | Unblock an IP |
| POST   | `/api/admin/ml/train`         | Trigger model retraining |
| GET    | `/api/admin/ml/anomalies`     | ML-flagged events |

---

## Attack Classification Logic

### Rule-Based (runs on every failed login)

```
window = last 5 minutes (configurable)

if unique_ips_targeting_username ≥ 10 AND unique_users_from_ip ≥ 5:
    → CREDENTIAL_STUFFING

elif unique_users_targeted_by_ip ≥ 5:
    → SPRAY (Password Spraying)

elif failed_attempts_from_ip ≥ 10:
    → BRUTE_FORCE

else:
    → NONE
```

### Machine Learning Pipeline

**Feature Engineering** (per IP, rolling 5-minute window):
- `failed_attempts_count` – total failures
- `unique_users_targeted` – distinct usernames tried
- `request_frequency` – requests per second
- `success_ratio` – fraction of successful logins
- `unique_ip_count_for_user` – how many IPs target the same username

**Models:**
- **Random Forest** (supervised, trained on labelled data) → probability of attack
- **Isolation Forest** (unsupervised) → anomaly score for novel threats

**Ensemble score** = 0.7 × RF + 0.3 × IsoForest

If score ≥ threshold (default 0.5) → flag as `ML_ANOMALY` and auto-block IP.

---

## Configuration

All settings live in `.env` (see `.env.example`):

```ini
MAX_FAILED_ATTEMPTS_PER_IP=10        # brute-force threshold
MAX_FAILED_WINDOW_SECONDS=300        # rolling window
BLOCK_DURATION_SECONDS=3600          # auto-block duration (1 hour)
SPRAY_UNIQUE_USERS_THRESHOLD=5       # spray detection
STUFFING_UNIQUE_IPS_THRESHOLD=10     # stuffing detection
ANOMALY_THRESHOLD=0.5                # ML confidence threshold
```

---

## Database Schema

```sql
users            – id, username, email, hashed_password, role, is_active, created_at
login_logs       – id, timestamp, ip_address, attempted_username, status, attack_type, ml_score
blocked_ips      – id, ip_address, reason, attack_type, blocked_at, expires_at, is_active
active_sessions  – id, user_id, token_jti, ip_address, logged_in_at, last_active, is_valid
ml_anomalies     – id, detected_at, ip_address, ml_score, features, action_taken
```

---

## Project Structure

```
bruteforce_detection/
├── main.py                        # FastAPI app entry point
├── config.py                      # Settings (pydantic-settings)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
│
├── backend/
│   ├── api/
│   │   ├── auth.py                # Auth endpoints + JWT session management
│   │   └── admin.py               # Admin endpoints
│   ├── middleware/
│   │   └── ip_blocker.py          # IPBlockMiddleware + rule-based classifier
│   ├── ml/
│   │   └── pipeline.py            # Feature engineering + model training + inference
│   ├── models/
│   │   ├── models.py              # SQLAlchemy ORM models
│   │   └── database.py            # Engine + session factory
│   └── utils/
│       └── security.py            # Password hashing + JWT helpers
│
├── frontend/
│   ├── static/css/style.css       # Design system (monochrome)
│   └── templates/
│       ├── auth/
│       │   ├── login.html
│       │   └── register.html
│       └── dashboard/
│           ├── user.html           # Regular user dashboard
│           └── admin.html          # Admin dashboard
│
├── scripts/
│   └── seed.py                    # DB seeder + initial ML training
│
└── ml/                            # Generated: model.joblib, scaler.joblib
```
