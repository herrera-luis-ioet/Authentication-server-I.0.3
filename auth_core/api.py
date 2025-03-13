"""
API router and Pydantic models for the Authentication Core Component.

This module provides FastAPI router with authentication endpoints and
Pydantic models for request/response validation.
"""
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Union

from fastapi import APIRouter, Body, HTTPException, Query, Request, status
from pydantic import BaseModel, EmailStr, Field, validator

# We'll import Depends lazily when needed to avoid circular imports with asyncio

# Import error classes and models to avoid circular imports
from auth_core.auth import (
    AccountLockedError, AuthError, InvalidCredentialsError, 
    UserExistsError, UserNotFoundError
)
from auth_core.models import AuthAttempt, AuthAttemptResult, User, UserRole
from auth_core.security import is_account_locked, get_lockout_time, MAX_LOGIN_ATTEMPTS
from auth_core.token import TokenError, TokenExpiredError, TokenInvalidError, TokenRevokedError

# Function imports will be done at function level to avoid circular imports

# Create API router
router = APIRouter(tags=["authentication"])


# Pydantic models for request/response
class UserLoginRequest(BaseModel):
    """Request model for user login."""
    username: str = Field(..., description="Username or email")
    password: str = Field(..., description="User password")


class UserRegistrationRequest(BaseModel):
    """Request model for user registration."""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=8, description="Password")
    auto_login: bool = Field(False, description="Automatically login after registration")


class TokenResponse(BaseModel):
    """Response model for token operations."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: Optional[str] = Field(None, description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")


class TokenRefreshRequest(BaseModel):
    """Request model for token refresh."""
    refresh_token: str = Field(..., description="JWT refresh token")


class TokenValidationRequest(BaseModel):
    """Request model for token validation."""
    token: str = Field(..., description="JWT token to validate")
    token_type: Optional[str] = Field(None, description="Expected token type")


class TokenValidationResponse(BaseModel):
    """Response model for token validation."""
    valid: bool = Field(..., description="Whether the token is valid")
    user_id: Optional[int] = Field(None, description="User ID from the token")
    username: Optional[str] = Field(None, description="Username from the token")
    token_type: Optional[str] = Field(None, description="Token type")
    expires_at: Optional[datetime] = Field(None, description="Token expiration time")


class LogoutRequest(BaseModel):
    """Request model for logout."""
    token: str = Field(..., description="JWT token to revoke")
    all_devices: bool = Field(False, description="Logout from all devices")


class PasswordChangeRequest(BaseModel):
    """Request model for password change."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")


class ErrorResponse(BaseModel):
    """Response model for errors."""
    detail: str = Field(..., description="Error detail")


class SuccessResponse(BaseModel):
    """Response model for successful operations."""
    message: str = Field(..., description="Success message")
    details: Optional[Dict] = Field(None, description="Additional details")


# API endpoints
@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"model": ErrorResponse, "description": "Account locked"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
    summary="Authenticate user and get tokens",
    description="Authenticate a user with username/email and password, and return access and refresh tokens.",
)
async def login(
    request: Request,
    login_data: UserLoginRequest,
):
    """
    Authenticate a user and generate access and refresh tokens.
    
    Args:
        request: FastAPI request object.
        login_data: User login credentials.
        
    Returns:
        TokenResponse with access and refresh tokens.
        
    Raises:
        HTTPException: If authentication fails.
    """
    try:
        # Get client IP and user agent
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent")
        
        # Import at function level to avoid circular imports
        from auth_core.auth import authenticate_user
        from auth_core.database import session_scope
        
        # First check if the account is locked due to too many failed attempts
        with session_scope() as session:
            # Try to find the user first
            from auth_core.auth import AuthenticationManager
            auth_manager = AuthenticationManager(session)
            user = auth_manager._find_user(session, login_data.username)
            
            if user:
                # Check for user-specific lockout
                user_failures = session.query(AuthAttempt).filter(
                    AuthAttempt.user_id == user.id,
                    AuthAttempt.result == AuthAttemptResult.FAILURE,
                    AuthAttempt.attempt_time >= datetime.utcnow() - timedelta(minutes=30)
                ).all()
                
                # Also check for username-based failures
                username_failures = AuthAttempt.get_recent_failures(
                    session, client_ip, minutes=30, username=user.username
                )
                
                # Create a set of IDs from user_failures to check for duplicates
                user_failure_ids = {attempt.id for attempt in user_failures}
                
                # Only add username_failures that aren't already counted in user_failures
                unique_username_failures = [
                    attempt for attempt in username_failures 
                    if attempt.id not in user_failure_ids
                ]
                
                total_failures = len(user_failures) + len(unique_username_failures)
                
                # Check if account is locked
                if is_account_locked(total_failures):
                    lockout_time = get_lockout_time()
                    raise AccountLockedError(
                        f"Account locked due to too many failed login attempts. "
                        f"Try again after {lockout_time.strftime('%H:%M:%S')}."
                    )
        
        # Authenticate user
        user, tokens = authenticate_user(
            login_data.username,
            login_data.password,
            client_ip,
            user_agent
        )
        
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"]
        )
        
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    except AccountLockedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )


@router.post(
    "/register",
    response_model=Union[TokenResponse, SuccessResponse],
    status_code=status.HTTP_201_CREATED,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid registration data"},
        409: {"model": ErrorResponse, "description": "User already exists"},
    },
    summary="Register a new user",
    description="Register a new user with username, email, and password. Optionally auto-login after registration.",
)
async def register(
    request: Request,
    registration_data: UserRegistrationRequest,
):
    """
    Register a new user.
    
    Args:
        request: FastAPI request object.
        registration_data: User registration data.
        
    Returns:
        TokenResponse with tokens if auto_login is True, otherwise SuccessResponse.
        
    Raises:
        HTTPException: If registration fails.
    """
    try:
        # Get client IP and user agent
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent")
        
        # Import at function level to avoid circular imports
        from auth_core.auth import register_user
        
        # Register user
        user, tokens = register_user(
            registration_data.username,
            registration_data.email,
            registration_data.password,
            UserRole.USER,
            registration_data.auto_login,
            client_ip if registration_data.auto_login else None,
            user_agent if registration_data.auto_login else None
        )
        
        if tokens:
            return TokenResponse(
                access_token=tokens["access_token"],
                refresh_token=tokens["refresh_token"],
                token_type=tokens["token_type"]
            )
        else:
            return SuccessResponse(
                message="User registered successfully",
                details={"username": user.username, "email": user.email}
            )
            
    except UserExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid refresh token"},
        403: {"model": ErrorResponse, "description": "Token revoked or expired"},
    },
    summary="Refresh access token",
    description="Generate a new access token using a valid refresh token.",
)
async def refresh(
    refresh_request: TokenRefreshRequest,
):
    """
    Refresh an access token using a refresh token.
    
    Args:
        refresh_request: Token refresh request data.
        
    Returns:
        TokenResponse with new access token.
        
    Raises:
        HTTPException: If token refresh fails.
    """
    try:
        # Import at function level to avoid circular imports
        from auth_core.token import refresh_access_token
        
        # Refresh the token
        tokens = refresh_access_token(refresh_request.refresh_token)
        
        return TokenResponse(
            access_token=tokens["access_token"],
            token_type=tokens["token_type"]
        )
        
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Refresh token has expired"
        )
    except TokenRevokedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Refresh token has been revoked"
        )
    except TokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post(
    "/validate",
    response_model=TokenValidationResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid token"},
    },
    summary="Validate a token",
    description="Validate a JWT token and return its details if valid.",
)
async def validate(
    validation_request: TokenValidationRequest,
):
    """
    Validate a JWT token.
    
    Args:
        validation_request: Token validation request data.
        
    Returns:
        TokenValidationResponse with token details if valid.
        
    Raises:
        HTTPException: If token validation fails.
    """
    try:
        # Import at function level to avoid circular imports
        from auth_core.token import validate_token
        
        # Validate the token
        payload = validate_token(
            validation_request.token,
            validation_request.token_type
        )
        
        # Extract token data
        user_id = int(payload.get("sub"))
        username = payload.get("username")
        token_type = payload.get("type")
        expires_at = datetime.fromtimestamp(payload.get("exp"))
        
        return TokenValidationResponse(
            valid=True,
            user_id=user_id,
            username=username,
            token_type=token_type,
            expires_at=expires_at
        )
        
    except TokenError as e:
        # Return invalid but don't raise an exception
        return TokenValidationResponse(valid=False)


@router.post(
    "/logout",
    response_model=SuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid logout request"},
    },
    summary="Logout user",
    description="Revoke a user's token(s) to log them out.",
)
async def logout(
    logout_request: LogoutRequest,
):
    """
    Logout a user by revoking their token(s).
    
    Args:
        logout_request: Logout request data.
        
    Returns:
        SuccessResponse indicating logout status.
        
    Raises:
        HTTPException: If logout fails.
    """
    try:
        if logout_request.all_devices:
            # Import at function level to avoid circular imports
            from auth_core.token import get_user_id_from_token
            from auth_core.auth import logout_user_all_devices
            
            # Get user ID from token
            user_id = get_user_id_from_token(logout_request.token)
            
            # Logout from all devices
            tokens_revoked = logout_user_all_devices(user_id)
            
            return SuccessResponse(
                message="Logged out from all devices",
                details={"tokens_revoked": tokens_revoked}
            )
        else:
            # Import at function level to avoid circular imports
            from auth_core.auth import logout_user
            
            # Logout from current device
            success = logout_user(logout_request.token)
            
            if success:
                return SuccessResponse(message="Logged out successfully")
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to logout"
                )
                
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/password",
    response_model=SuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        404: {"model": ErrorResponse, "description": "User not found"},
    },
    summary="Change password",
    description="Change a user's password.",
)
async def change_user_password(
    request: Request,
    password_request: PasswordChangeRequest,
    token: str = None,
):
    """
    Change a user's password.
    
    Args:
        request: FastAPI request object.
        password_request: Password change request data.
        token: JWT token from Authorization header.
        
    Returns:
        SuccessResponse indicating password change status.
        
    Raises:
        HTTPException: If password change fails.
    """
    # Import Depends lazily to avoid circular imports with asyncio
    from fastapi import Depends
    
    # Get token from Authorization header if not provided
    if token is None:
        token_extractor = lambda x: x.headers.get("Authorization").split(" ")[1] if x.headers.get("Authorization") else None
        token = token_extractor(request)
    try:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        # Import at function level to avoid circular imports
        from auth_core.token import get_user_id_from_token
        from auth_core.auth import change_password
        
        # Get user ID from token
        user_id = get_user_id_from_token(token)
        
        # Change password
        success = change_password(
            user_id,
            password_request.current_password,
            password_request.new_password
        )
        
        if success:
            return SuccessResponse(message="Password changed successfully")
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to change password"
            )
            
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
