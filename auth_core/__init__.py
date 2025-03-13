"""
Authentication Core Component.

This package provides core authentication functionality including:
- User management with secure password storage
- JWT token generation and validation
- Token tracking and blacklisting
- Brute force attack prevention
"""

__version__ = "0.1.0"

# Export config constants first to avoid circular imports
from auth_core.config import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
)

# Export database functions next as they're needed by models
from auth_core.database import (
    Base,
    init_db,
    get_session,
    session_scope,
)

# Export models next as they're needed by token
from auth_core.models import (
    User,
    UserRole,
    Token,
    TokenType,
    TokenStatus,
    AuthAttempt,
    AuthAttemptResult,
)

# Export token functions last as they depend on the above modules
from auth_core.token import (
    create_access_token,
    create_refresh_token,
    create_token_pair,
    validate_token,
    refresh_access_token,
    revoke_token,
    revoke_all_user_tokens,
    get_user_id_from_token,
    get_token_data,
    clean_expired_tokens,
    is_token_valid,
    get_token_expiration,
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
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
    
    # Token management
    "create_access_token",
    "create_refresh_token",
    "create_token_pair",
    "validate_token",
    "refresh_access_token",
    "revoke_token",
    "revoke_all_user_tokens",
    "get_user_id_from_token",
    "get_token_data",
    "clean_expired_tokens",
    "is_token_valid",
    "get_token_expiration",
    "TokenError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenRevokedError",
    
    # Config constants
    "TOKEN_TYPE_ACCESS",
    "TOKEN_TYPE_REFRESH",
]
