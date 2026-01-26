from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router as api_router
from core.config import AppSettings
from core.rate_limit import limiter
from slowapi.middleware import SlowAPIMiddleware

from core.logging import setup_logging
from loguru import logger

from core.middleware import log_request

settings = AppSettings()

app = FastAPI(title=settings.app_name)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

app.middleware("http")(log_request)
logger.info("Application initialized")