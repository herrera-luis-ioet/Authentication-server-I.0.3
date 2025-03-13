"""
Dependency injection for the Authentication Core Component.

This module provides FastAPI dependency functions for authentication,
authorization, and other security-related functionality.
"""
from typing import Optional, Union

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth_core.database import get_session, session_scope
from auth_core.models import User, UserRole
from auth_core.security import RateLimitExceededError, default_rate_limiter
from auth_core.token import (TokenError, TokenExpiredError, TokenInvalidError,
                           TokenRevokedError, get_token_data, get_user_id_from_token,
                           validate_token)

# Security scheme for JWT tokens
security = HTTPBearer(auto_error=False)


# PUBLIC_INTERFACE
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> User:
    """
    Get the current authenticated user from the JWT token.
    
    Args:
        request: FastAPI request object.
        credentials: HTTP Authorization credentials.
        
    Returns:
        User object for the authenticated user.
        
    Raises:
        HTTPException: If authentication fails.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    try:
        # Validate the token
        payload = validate_token(token)
        
        # Get user ID from token
        user_id = int(payload.get("sub"))
        
        # Get user from database
        with session_scope() as session:
            user = session.query(User).filter(User.id == user_id).first()
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is inactive"
                )
            
            return user
            
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenRevokedError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


# PUBLIC_INTERFACE
async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get the current active user.
    
    Args:
        current_user: User object from get_current_user dependency.
        
    Returns:
        User object for the authenticated active user.
        
    Raises:
        HTTPException: If the user is inactive.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    return current_user


# PUBLIC_INTERFACE
async def get_current_admin_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get the current admin user.
    
    Args:
        current_user: User object from get_current_active_user dependency.
        
    Returns:
        User object for the authenticated admin user.
        
    Raises:
        HTTPException: If the user is not an admin.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


# PUBLIC_INTERFACE
async def get_optional_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """
    Get the current user if authenticated, or None if not.
    
    Args:
        request: FastAPI request object.
        credentials: HTTP Authorization credentials.
        
    Returns:
        User object if authenticated, None otherwise.
    """
    if not credentials:
        return None
    
    token = credentials.credentials
    
    try:
        # Validate the token
        payload = validate_token(token)
        
        # Get user ID from token
        user_id = int(payload.get("sub"))
        
        # Get user from database
        with session_scope() as session:
            user = session.query(User).filter(User.id == user_id).first()
            return user
            
    except TokenError:
        return None


# PUBLIC_INTERFACE
async def get_token_from_header(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> str:
    """
    Extract JWT token from Authorization header.
    
    Args:
        credentials: HTTP Authorization credentials.
        
    Returns:
        JWT token string.
        
    Raises:
        HTTPException: If no token is provided.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return credentials.credentials


# PUBLIC_INTERFACE
class RateLimitedRoute:
    """
    Rate limiting dependency for API routes.
    
    Limits the number of requests from a specific IP address.
    """
    
    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: int = 60,
        error_message: str = "Rate limit exceeded"
    ):
        """
        Initialize the rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the window.
            window_seconds: Time window in seconds.
            error_message: Error message to return when rate limit is exceeded.
        """
        self.rate_limiter = default_rate_limiter
        self.rate_limiter.max_requests = max_requests
        self.rate_limiter.window_seconds = window_seconds
        self.error_message = error_message
    
    async def __call__(self, request: Request):
        """
        Check if the request is rate limited.
        
        Args:
            request: FastAPI request object.
            
        Raises:
            HTTPException: If the rate limit is exceeded.
        """
        client_ip = request.client.host
        
        try:
            self.rate_limiter.add_request(client_ip)
        except RateLimitExceededError:
            reset_time = self.rate_limiter.get_reset_time(client_ip)
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=self.error_message,
                headers={
                    "Retry-After": str(int(reset_time - time.time())) if reset_time else "60",
                    "X-RateLimit-Limit": str(self.rate_limiter.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(reset_time)) if reset_time else "",
                }
            )


# Rate limiter for sensitive endpoints
auth_rate_limiter = RateLimitedRoute(
    max_requests=10,
    window_seconds=60,
    error_message="Too many authentication attempts, please try again later"
)


# Import time module for rate limiter
import time