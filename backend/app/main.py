import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.dns import router as dns_router
from app.api.domain import router as domain_router
from app.api.investigations import router as investigations_router
from app.api.ioc import router as ioc_router
from app.api.subnet import router as subnet_router
from app.api.stats import router as stats_router
from app.core.config import get_settings
from app.core.database import initialize_database
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.paths import BUNDLE_DIR
from app.core.rate_limit import AnalyzeRateLimitMiddleware


APP_VERSION = "0.1.0"
FRONTEND_DIRECTORY = Path(
    os.environ.get(
        "CYBERIP_FRONTEND_DIR",
        BUNDLE_DIR / "frontend",
    )
)


class RevalidatingStaticFiles(StaticFiles):
    """Serve the interface with revalidation on every request.

    Without an explicit policy a browser caches these files heuristically, so
    an updated page can be paired with a stale script from a previous version.
    Entity tags still answer unchanged files with 304, so revalidation stays
    cheap.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


def create_app() -> FastAPI:
    """Build and configure the CyberIP Analyzer ASGI application."""

    settings = get_settings()
    configure_logging()

    application = FastAPI(
        title="CyberIP Analyzer",
        description="Mini SOC Investigation and Threat Intelligence Tool",
        version=APP_VERSION,
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )
    application.add_middleware(
        AnalyzeRateLimitMiddleware,
        requests=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window,
    )
    register_exception_handlers(application)
    application.include_router(dns_router)
    application.include_router(domain_router)
    application.include_router(investigations_router)
    application.include_router(ioc_router)
    application.include_router(stats_router)
    application.include_router(subnet_router)

    @application.get("/api/health", tags=["system"])
    async def health() -> dict[str, object]:
        return {
            "status": "ok",
            "version": APP_VERSION,
            "integrations": {
                "virustotal": bool(settings.virustotal_api_key),
                "abuseipdb": bool(settings.abuseipdb_api_key),
                "threatfox": bool(settings.threatfox_api_key),
                "urlhaus": bool(settings.urlhaus_api_key or settings.threatfox_api_key),
                "ai_analyst": bool(settings.ai_api_key),
            },
        }

    application.mount(
        "/",
        RevalidatingStaticFiles(directory=FRONTEND_DIRECTORY, html=True),
        name="frontend",
    )
    return application


app = create_app()
