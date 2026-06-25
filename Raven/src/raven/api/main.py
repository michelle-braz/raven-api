from __future__ import annotations

import logging
import os
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from raven.api.auth import require_api_key
from raven.api.beta_keys import is_valid_beta_key, register_with_auth
from raven.api.beta.router import router as beta_router
from raven.api.v1.router import router as v1_router
from raven.sentinel.core.engine import evaluate as sentinel_evaluate
from raven.sentinel.pipeline.action_layer.notifier import ActionDispatcher, LogChannel
from raven.sentinel.pipeline.app import IngestionPipeline, SignalWindow
from raven.sentinel.pipeline.data_layer.schemas import Severity, SourceType
from raven.sentinel.pipeline.intelligence_layer.engine import build_engine

_log = logging.getLogger(__name__)
COMPANY_NAME = "NOVA"
PRODUCT_NAME = "RAVEN"

# ── Error code mapping ────────────────────────────────────────────────────────

_HTTP_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    422: "validation_error",
    429: "rate_limit_exceeded",
    500: "internal_server_error",
}

# ── Lifespan — pipeline initialization for /v1 endpoints ─────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create shared pipeline state once at startup. Destroyed on shutdown."""
    register_with_auth()
    app.state.started_at = time.monotonic()
    app.state.pipeline = IngestionPipeline(
        engine=build_engine(),
        dispatcher=ActionDispatcher([LogChannel(min_severity=Severity.LOW)]),
        window=SignalWindow(),
    )
    yield


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=f"{PRODUCT_NAME} Risk API",
    version="1.0.0",
    description=(
        f"## {PRODUCT_NAME} Risk Intelligence API\n\n"
        "Two independent scoring engines are available:\n\n"
        "| Endpoint | Engine | Score range | Severity bands |\n"
        "|---|---|---|---|\n"
        "| `POST /evaluate` | Rule-based (legacy) | Integer **0 – 100** | LOW / MEDIUM / HIGH |\n"
        "| `POST /v1/analyze` | Sentinel 4-layer pipeline | Float **0.0 – 1.0** | LOW / MEDIUM / HIGH / CRITICAL |\n\n"
        "All protected endpoints require the `X-API-Key` header.\n\n"
        "All error responses share the envelope `{\"error\": \"...\", \"code\": \"...\"}`."
    ),
    docs_url="/docs",
    lifespan=lifespan,
)

app.include_router(v1_router)
app.include_router(beta_router)

# ── Closed-beta access gate ───────────────────────────────────────────────────
# Registered BEFORE CORSMiddleware so CORS is the outermost layer — error
# responses (401/403) from this gate still carry correct CORS headers.

_BETA_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/", "/openapi.json", "/health", "/status", "/favicon.ico",
})
_BETA_PUBLIC_PREFIXES: tuple[str, ...] = ("/docs", "/redoc")
_BETA_MASTER: str | None = os.getenv("RAVEN_API_KEY")


@app.middleware("http")
async def beta_access_gate(request: Request, call_next):
    path = request.url.path
    if (
        request.method == "OPTIONS"
        or path in _BETA_PUBLIC_PATHS
        or any(path.startswith(p) for p in _BETA_PUBLIC_PREFIXES)
    ):
        return await call_next(request)
    api_key = request.headers.get("x-api-key")  # Starlette normalises headers to lowercase
    if not api_key:
        return JSONResponse(
            status_code=401,
            content={"error": "missing_api_key", "message": "API key required (beta access)"},
        )
    if (_BETA_MASTER and api_key == _BETA_MASTER) or is_valid_beta_key(api_key):
        return await call_next(request)
    return JSONResponse(
        status_code=403,
        content={"error": "invalid_api_key", "message": "Invalid or inactive beta key"},
    )


# ── CORS ──────────────────────────────────────────────────────────────────────
# Origins are configurable via CORS_ORIGINS (comma-separated). Default "*" is
# intentionally open; set a specific origin list in production.
_cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)

# ── Exception handlers — consistent {"error": ..., "code": ...} envelope ─────

@app.exception_handler(404)
async def _not_found(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "Not found.", "code": "not_found"})


@app.exception_handler(429)
async def _rate_limited(_: Request, exc: Exception) -> JSONResponse:
    detail = getattr(exc, "detail", "Too many requests.")
    return JSONResponse(
        status_code=429,
        content={
            "error": detail,
            "code": "rate_limit_exceeded",
            "hint": "Back off and retry with exponential delay.",
        },
    )


@app.exception_handler(HTTPException)
async def _http_error(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "code": _HTTP_CODES.get(exc.status_code, "error"),
        },
    )


@app.exception_handler(RequestValidationError)
async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": "Request validation failed.", "code": "validation_error"},
    )


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    request_id = str(uuid.uuid4())
    _log.error(
        "Unhandled exception request_id=%s method=%s path=%s\n%s",
        request_id,
        request.method,
        request.url.path,
        traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "An unexpected error occurred. Please contact support.",
            "code": "internal_server_error",
            "request_id": request_id,
        },
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing() -> str:
    html = Path(__file__).parent / "landing.html"
    if html.exists():
        return html.read_text(encoding="utf-8")
    return "<html><body><h1>RAVEN by NOVA</h1><p>Real-time risk intelligence.</p></body></html>"


@app.get("/health", tags=["ops"])
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "raven-risk-api", "version": "1.0.0"}


@app.get(
    "/status",
    tags=["ops"],
    summary="Service status",
    description="Returns service metadata and uptime. No auth required. Suitable for load-balancer health probes.",
)
async def status(request: Request) -> dict[str, object]:
    return {
        "service": "raven-risk-api",
        "version": request.app.version,
        "uptime_seconds": int(time.monotonic() - request.app.state.started_at),
        "environment": os.getenv("ENVIRONMENT", "development"),
    }


@app.post(
    "/evaluate",
    summary="Score an event (rule-based legacy engine)",
    description=(
        "Rule-based scoring engine. Returns an **integer** risk score (0 – 100) "
        "and a level band.\n\n"
        "**Score thresholds:** LOW < 40 · MEDIUM 40–69 · HIGH ≥ 70\n\n"
        "**Scoring rules:**\n"
        "- `action=login_failed` → +30\n"
        "- `attempts ≥ 3` → +40\n"
        "- Known suspicious IP → +10\n\n"
        "For ML-based multi-factor scoring with float scores (0.0 – 1.0), "
        "four severity bands, and recurrence detection, use `POST /v1/analyze`."
    ),
    tags=["evaluate"],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string", "description": "Event description."},
                            "action": {"type": "string", "description": "Event action (e.g. login_failed, page_view)."},
                            "attempts": {"type": "integer", "description": "Number of attempts.", "default": 0},
                            "ip": {"type": "string", "description": "Source IP address."},
                            "user_id": {"type": "string", "description": "User identifier."},
                            "source": {"type": "string", "description": "Signal origin.", "default": "unknown"},
                        },
                    },
                    "examples": {
                        "high_risk": {
                            "summary": "High-risk login attempt (score 80, HIGH)",
                            "value": {
                                "message": "failed login from suspicious IP",
                                "action": "login_failed",
                                "attempts": 5,
                                "ip": "192.168.1.1",
                                "user_id": "user_001",
                                "source": "application",
                            },
                        },
                        "low_risk": {
                            "summary": "Low-risk page view (score 0, LOW)",
                            "value": {
                                "message": "user viewed dashboard",
                                "action": "page_view",
                                "attempts": 0,
                                "ip": "8.8.8.8",
                                "user_id": "user_002",
                                "source": "application",
                            },
                        },
                    },
                }
            },
        }
    },
)
async def evaluate_event(
    request: Request,
    auth: dict[str, str] = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    # Validate source; default to UNKNOWN for backward compatibility.
    raw_source = body.get("source", SourceType.UNKNOWN.value)
    try:
        source_value = SourceType(raw_source).value
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid source '{raw_source}'. Must be one of: {[s.value for s in SourceType]}",
        )

    result = sentinel_evaluate(body)
    result["message"] = str(body.get("message", ""))
    result["source"] = source_value
    result["plan"] = auth["tier"]
    return result


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "raven.api.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
        reload=False,
    )
