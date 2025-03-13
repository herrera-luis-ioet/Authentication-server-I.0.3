"""
Authentication Core Component - FastAPI Application.

This is the main entry point for the Authentication Core Component,
providing a FastAPI application with authentication endpoints.
"""
# Import asyncio first to ensure it's fully initialized
import asyncio
import logging
import os  # Keep this import for path operations
from typing import Dict, List, Optional, Union

# Third-party imports
import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

# Local application imports
from auth_core import __version__
from auth_core.api import router as auth_router
from auth_core.config import settings
from auth_core.database import init_db
from auth_core.token import TokenError

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT,
)
logger = logging.getLogger("auth_core")

# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    debug=settings.DEBUG,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security scheme for OpenAPI documentation
security_scheme = HTTPBearer(auto_error=False)
app.swagger_ui_init_oauth = {
    "usePkceWithAuthorizationCodeGrant": True,
    "useBasicAuthenticationWithAccessCodeGrant": True,
}


# Exception handlers
@app.exception_handler(TokenError)
async def token_error_handler(request: Request, exc: TokenError):
    """Handle token-related errors."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# Health check endpoint
@app.get(
    "/health",
    tags=["health"],
    summary="Health check",
    description="Check if the API is running.",
)
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "version": __version__}


# Include authentication router
app.include_router(auth_router, prefix="/auth")


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the application on startup."""
    logger.info("Initializing Authentication Core API")
    
    # Initialize database
    init_db(settings.DATABASE_URL)
    
    logger.info("Authentication Core API initialized")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on shutdown."""
    logger.info("Shutting down Authentication Core API")


# Run the application if executed directly
if __name__ == "__main__":
    # Run the application using settings
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD,
        log_level=settings.LOG_LEVEL.lower(),
    )
