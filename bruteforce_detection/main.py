"""
BruteShield – Brute Force Detection System
Main FastAPI application
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.auth import router as auth_router
from backend.api.admin import router as admin_router
from backend.middleware.ip_blocker import IPBlockMiddleware
from backend.models.database import init_db
from backend.ml.pipeline import train_model, ThreatDetector
from config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s – %(message)s",
)
log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialise DB tables and pre-load ML model."""
    log.info("Starting BruteShield …")
    await init_db()

    from pathlib import Path
    if not Path(settings.MODEL_PATH).exists():
        log.info("No model found – training with synthetic data …")
        train_model()
    ThreatDetector.get()

    log.info("BruteShield ready.")
    yield
    log.info("BruteShield shutting down.")


app = FastAPI(
    title="BruteShield – Brute Force Detection System",
    version="1.0.0",
    description="ML-powered authentication security with real-time attack classification.",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# FIX 1: Cannot use allow_origins=["*"] with allow_credentials=True.
# Browsers reject cookies when the origin is a wildcard.
# List your actual frontend origin(s) explicitly instead.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        # Add any other origins your frontend runs on, e.g.:
        # "https://yourdomain.com",
    ],
    allow_credentials=True,   # required for cookies to be sent cross-origin
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── IP Block Middleware ───────────────────────────────────────────────────────
app.add_middleware(IPBlockMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(admin_router)

# ── Static files & templates ──────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
templates = Jinja2Templates(directory="frontend/templates")


# ── Page routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("auth/login.html", {"request": request})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("auth/register.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard/user.html", {"request": request})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("dashboard/admin.html", {"request": request})


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}