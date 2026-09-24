from fastapi import APIRouter
from app.api.routes.health import router as health_router
from app.api.routes.auth import router as auth_router
from app.api.routes.scans import router as scans_router
from app.api.routes.ml import router as ml_router
from app.api.routes.analyze import router as analyze_router
from app.api.routes.visual_analysis import router as visual_analysis_router
from app.api.routes.intelligence import router as intelligence_router
from app.api.routes.notifications import router as notifications_router
from app.api.routes.analytics import router as analytics_router
from app.api.routes.threat_intel import router as threat_intel_router
from app.api.routes.models import router as models_router
from app.api.routes.admin import router as admin_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(scans_router)
api_router.include_router(ml_router)
api_router.include_router(analyze_router)
api_router.include_router(visual_analysis_router)
api_router.include_router(intelligence_router)
api_router.include_router(notifications_router)
api_router.include_router(analytics_router)
api_router.include_router(threat_intel_router)
api_router.include_router(models_router)
api_router.include_router(admin_router)


@api_router.get("/", tags=["API Root"])
async def api_v1_index():
    """API v1 discovery endpoint providing system status and route index."""
    return {
        "name": "PhishGuard AI API",
        "version": "1.0.0-phase8",
        "api_version": "v1",
        "status": "operational",
        "health": "/api/v1/health",
        "endpoints": {
            "health": "/api/v1/health",
            "auth_login": "/api/v1/auth/login",
            "auth_register": "/api/v1/auth/register",
            "scans": "/api/v1/scans",
            "analytics": "/api/v1/analytics/overview",
            "threat_intel": "/api/v1/threat-intel/indicators",
            "models": "/api/v1/models/transparency",
        },
    }

