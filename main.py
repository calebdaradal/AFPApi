from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router as api_router
from core.config import AppSettings
from core.rate_limit import limiter
from slowapi.middleware import SlowAPIMiddleware

from core.logging import setup_logging
from loguru import logger

from core.middleware import log_request

# Initialize settings first
settings = AppSettings()

# Initialize logging BEFORE using logger - this sets up loguru to output logs
setup_logging(settings.debug)

# Create FastAPI app
app = FastAPI(title=settings.app_name)

# Configure CORS middleware - allows cross-origin requests from Flutter app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes with /api prefix - matches Flutter app's baseUrl
app.include_router(api_router, prefix="/api")

# Setup rate limiting
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

# Add request logging middleware - logs all incoming requests and responses
app.middleware("http")(log_request)

# Log that application has started - this will now actually show up!
logger.info("Application initialized")