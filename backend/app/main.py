"""
main.py  Sentinel FastAPI application entry point.
"""

import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.schemas import HealthResponse

LOG_LEVEL = os.environ.get("SENTINEL_LOG_LEVEL", "INFO")
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Sentinel Cybersecurity Analysis API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="sentinel-backend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=config.API_HOST, port=config.API_PORT, reload=True, log_level=LOG_LEVEL.lower())
