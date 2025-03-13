"""
JWT configuration settings for the Authentication Core Component.

This module provides configuration settings for JWT token generation,
validation, and management.
"""
from datetime import timedelta
from typing import Dict, Optional, Union

from auth_core.config.settings import settings

# Token settings
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"

# PUBLIC_INTERFACE
def get_jwt_settings() -> Dict[str, Union[str, int]]:
    """
    Get JWT configuration settings.
    
    Returns:
        Dictionary containing JWT configuration settings.
    """
    return {
        "secret_key": settings.JWT_SECRET_KEY,
        "algorithm": settings.JWT_ALGORITHM,
        "access_token_expire_minutes": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
        "refresh_token_expire_days": settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
    }

# PUBLIC_INTERFACE
def get_token_expiry(token_type: str) -> timedelta:
    """
    Get token expiry time based on token type.
    
    Args:
        token_type: Type of token (access or refresh).
        
    Returns:
        Timedelta representing token expiry time.
    """
    if token_type == TOKEN_TYPE_ACCESS:
        return timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    elif token_type == TOKEN_TYPE_REFRESH:
        return timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    else:
        raise ValueError(f"Invalid token type: {token_type}")
