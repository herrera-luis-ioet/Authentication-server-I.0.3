"""
Configuration module for the Authentication Core Component.

This module provides configuration settings for the Authentication Core Component.
"""

from auth_core.config.jwt_config import (
    get_jwt_settings,
    get_token_expiry,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH
)
from auth_core.config.settings import settings, get_settings

__all__ = [
    "get_jwt_settings",
    "get_token_expiry",
    "TOKEN_TYPE_ACCESS",
    "TOKEN_TYPE_REFRESH",
    "settings",
    "get_settings"
]
