"""
Authentication Core Component.

This package provides core authentication functionality including:
- User management with secure password storage
- JWT token generation and validation
- Token tracking and blacklisting
- Brute force attack prevention
"""

__version__ = "0.1.0"

# Export models
from auth_core.models import (
    User,
    UserRole,
    Token,
    TokenType,
    TokenStatus,
    AuthAttempt,
    AuthAttemptResult,
)

# Export database functions
from auth_core.database import (
    Base,
    init_db,
    get_session,
    session_scope,
)

__all__ = [
    # Models
    "User",
    "UserRole",
    "Token",
    "TokenType",
    "TokenStatus",
    "AuthAttempt",
    "AuthAttemptResult",
    
    # Database
    "Base",
    "init_db",
    "get_session",
    "session_scope",
]