"""
Centralized configuration management for the Authentication Core Component.

This module provides a centralized configuration system using Pydantic BaseSettings
for managing all application settings including JWT, security, database, and API settings.

Note on Pydantic compatibility:
This module includes a compatibility layer to support both Pydantic v1 and v2.
In Pydantic v1, BaseSettings is in the pydantic module.
In Pydantic v2, BaseSettings is moved to pydantic_settings module.
The module uses model_config for Pydantic v2 configuration.
"""
import os
import secrets
from typing import Any, Dict, List, Optional, Union

from pydantic import (
    AnyHttpUrl,
    EmailStr,
    Field,
    PostgresDsn,
    SecretStr,
    validator
)

# Compatibility layer for Pydantic settings
# Try to import BaseSettings from pydantic_settings (Pydantic v2) first
# Fall back to importing from pydantic (Pydantic v1) if not available
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings


class Settings(BaseSettings):
    """
    Settings class for all application configuration.
    
    This class uses Pydantic's BaseSettings to manage all application configuration
    settings with environment variable overrides and validation.
    """
    # Application settings
    APP_NAME: str = "Authentication Core"
    APP_DESCRIPTION: str = "Authentication Core Component providing secure JWT token-based authentication"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = Field(default="development", env="APP_ENV")
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # API settings
    API_PREFIX: str = "/api"
    HOST: str = Field(default="0.0.0.0", env="HOST")
    PORT: int = Field(default=8000, env="PORT")
    RELOAD: bool = Field(default=False, env="RELOAD")
    
    # CORS settings
    CORS_ORIGINS: List[str] = Field(default=["*"], env="CORS_ORIGINS")
    
    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        """Parse CORS_ORIGINS from string to list."""
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    # Rate limiting settings
    RATE_LIMIT_ENABLED: bool = Field(default=True, env="RATE_LIMIT_ENABLED")
    RATE_LIMIT_REQUESTS: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_PERIOD_SECONDS: int = Field(default=60, env="RATE_LIMIT_PERIOD_SECONDS")
    
    # JWT settings
    JWT_SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        env="JWT_SECRET_KEY"
    )
    JWT_ALGORITHM: str = Field(default="HS256", env="JWT_ALGORITHM")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Security settings
    PASSWORD_MIN_LENGTH: int = Field(default=8, env="PASSWORD_MIN_LENGTH")
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    PASSWORD_REQUIRE_DIGIT: bool = Field(default=True, env="PASSWORD_REQUIRE_DIGIT")
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL")
    PASSWORD_SPECIAL_CHARS: str = Field(default="!@#$%^&*()-_=+[]{}|;:,.<>?", env="PASSWORD_SPECIAL_CHARS")
    
    # Account lockout settings
    MAX_LOGIN_ATTEMPTS: int = Field(default=5, env="MAX_LOGIN_ATTEMPTS")
    LOCKOUT_DURATION_MINUTES: int = Field(default=15, env="LOCKOUT_DURATION_MINUTES")
    
    # Password reset settings
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="PASSWORD_RESET_TOKEN_EXPIRE_MINUTES")
    
    # Database settings
    DATABASE_URL: Optional[str] = Field(default=None, env="DATABASE_URL")
    DATABASE_ECHO: bool = Field(default=False, env="DATABASE_ECHO")
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_url(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        """Set default SQLite database URL if not provided."""
        if isinstance(v, str):
            return v
        
        # Default to SQLite database in project root
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        return f"sqlite:///{os.path.join(base_dir, 'auth.db')}"
    
    # Logging settings
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        env="LOG_FORMAT"
    )
    LOG_FILE: Optional[str] = Field(default=None, env="LOG_FILE")
    
    # Configuration for Pydantic v2
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore"  # Allow extra fields from environment variables
    }


# Create a global settings instance
settings = Settings()


# PUBLIC_INTERFACE
def get_settings() -> Settings:
    """
    Get the application settings.
    
    Returns:
        Settings: The application settings instance.
    """
    return settings
