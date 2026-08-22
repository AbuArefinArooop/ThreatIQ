"""
ThreatIQ v4.0 -- Hardened FastAPI Application
"""
import logging, uuid as _uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.core.security import security_headers_middleware
from app.api.v1 import router as api_v1_router

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

ALLOWED_ORIGINS = [
    "http://localhost:8000", "http://localhost:3000",
    "http://127.0.0.1:8000", "http://127.0.0.1:3000",
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ThreatIQ v%s starting [%s]", settings.APP_VERSION, settings.ENVIRONMENT)
    if settings.ENVIRONMENT == "development":
        try:
            from app.db.session import init_db
            await init_db()
            logger.info("DB tables initialised")
        except Exception as exc:
            logger.warning("DB init skipped (%s) -- ensure Postgres is running", exc)
    yield
    logger.info("ThreatIQ shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-powered CTI platform -- production hardened",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

app.middleware("http")(security_headers_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],
    allow_headers=["Authorization","Content-Type","X-API-Key","X-Request-ID"],
    max_age=600,
)

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID", str(_uuid.uuid4())[:8])
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response

@app.exception_handler(Exception)
async def global_exc_handler(request: Request, exc: Exception):
    logger.error("Unhandled %s %s: %s", request.method, request.url.path, exc)
    if settings.DEBUG:
        import traceback
        return JSONResponse(status_code=500, content={"detail": str(exc), "trace": traceback.format_exc()})
    return JSONResponse(status_code=500, content={"detail": "Internal error. See X-Request-ID header."})

# ── API routes ─────────────────────────────────────────────────
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

# ── Health ─────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy", "version": settings.APP_VERSION}

@app.get("/ready", tags=["Health"])
async def ready():
    checks: dict = {}
    try:
        import redis as _r
        _r.Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, socket_timeout=2).ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unavailable"
    checks["status"] = "ready" if all(v=="ok" for v in checks.values()) else "degraded"
    return checks

# ── Static files + SPA ────────────────────────────────────────
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_ui():
        return FileResponse(str(static_dir / "index.html"))
