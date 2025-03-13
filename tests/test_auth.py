"""
Tests for the authentication functionality.

This module tests the user authentication, registration, and account management
functionality provided by the auth_core.auth module.
"""
import jwt
import pytest
from unittest.mock import patch

from auth_core.auth import (
    AccountLockedError,
    AuthenticationManager,
    AuthError,
    InvalidCredentialsError,
    UserExistsError,
    UserNotFoundError,
    authenticate_user,
    change_password,
    logout_user,
    logout_user_all_devices,
    register_user,
)
from auth_core.models import AuthAttempt, AuthAttemptResult, Token, TokenStatus, User, UserRole
from auth_core.security import MAX_LOGIN_ATTEMPTS


def test_authenticate_user_success(test_user, db_session):
    """Test successful user authentication."""
    # Authenticate user
    user, tokens = authenticate_user(
        username_or_email=test_user.username,
        password="password123",
        ip_address="127.0.0.1",
        user_agent="test-agent"
    )
    
    # Verify user
    assert user.id == test_user.id
    assert user.username == test_user.username
    
    # Verify tokens
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert "token_type" in tokens
    assert tokens["token_type"] == "bearer"
    
    # Verify authentication attempt was recorded
    auth_attempt = db_session.query(AuthAttempt).filter_by(user_id=user.id).first()
    assert auth_attempt is not None
    assert auth_attempt.result == AuthAttemptResult.SUCCESS
    assert auth_attempt.ip_address == "127.0.0.1"
    assert auth_attempt.user_agent == "test-agent"


def test_authenticate_user_with_email(test_user, db_session):
    """Test user authentication with email."""
    # Authenticate user with email
    user, tokens = authenticate_user(
        username_or_email=test_user.email,
        password="password123",
        ip_address="127.0.0.1"
    )
    
    # Verify user
    assert user.id == test_user.id
    assert user.email == test_user.email


def test_authenticate_user_not_found(db_session):
    """Test authentication with non-existent user."""
    # Attempt to authenticate non-existent user
    with pytest.raises(UserNotFoundError):
        authenticate_user(
            username_or_email="nonexistent",
            password="password123",
            ip_address="127.0.0.1"
        )
    
    # Verify failed attempt was recorded
    auth_attempt = db_session.query(AuthAttempt).first()
    assert auth_attempt is not None
    assert auth_attempt.result == AuthAttemptResult.FAILURE
    assert auth_attempt.ip_address == "127.0.0.1"
    assert auth_attempt.username_attempt == "nonexistent"


def test_authenticate_user_invalid_password(test_user, db_session):
    """Test authentication with invalid password."""
    # Attempt to authenticate with wrong password
    with pytest.raises(InvalidCredentialsError):
        authenticate_user(
            username_or_email=test_user.username,
            password="wrongpassword",
            ip_address="127.0.0.1"
        )
    
    # Verify failed attempt was recorded
    auth_attempt = db_session.query(AuthAttempt).filter_by(user_id=test_user.id).first()
    assert auth_attempt is not None
    assert auth_attempt.result == AuthAttemptResult.FAILURE
    assert auth_attempt.ip_address == "127.0.0.1"


def test_authenticate_user_inactive(inactive_user, db_session):
    """Test authentication with inactive user."""
    # Attempt to authenticate inactive user
    with pytest.raises(UserNotFoundError):
        authenticate_user(
            username_or_email=inactive_user.username,
            password="password123",
            ip_address="127.0.0.1"
        )


def test_authenticate_user_account_lockout(test_user, db_session):
    """Test account lockout after too many failed attempts."""
    # Create MAX_LOGIN_ATTEMPTS failed attempts
    for i in range(MAX_LOGIN_ATTEMPTS):
        auth_attempt = AuthAttempt(
            user_id=test_user.id,
            ip_address="127.0.0.1",
            result=AuthAttemptResult.FAILURE
        )
        db_session.add(auth_attempt)
    db_session.commit()
    
    # Attempt to authenticate
    with pytest.raises(AccountLockedError):
        authenticate_user(
            username_or_email=test_user.username,
            password="password123",
            ip_address="127.0.0.1"
        )


def test_register_user_success(db_session):
    """Test successful user registration."""
    # Register a new user
    user, tokens = register_user(
        username="newuser",
        email="new@example.com",
        password="Password123!",
        role=UserRole.USER,
        auto_login=False,
        is_test_user=True
    )
    
    # Verify user was created
    assert user.id is not None
    assert user.username == "newuser"
    assert user.email == "new@example.com"
    assert user.role == UserRole.USER
    assert user.is_active is True
    
    # Verify password was hashed
    assert user.hashed_password is not None
    assert user.hashed_password != "Password123!"
    
    # Verify no tokens were returned
    assert tokens is None
    
    # Verify user exists in database
    db_user = db_session.query(User).filter_by(username="newuser").first()
    assert db_user is not None
    assert db_user.id == user.id


def test_register_user_with_auto_login(db_session):
    """Test user registration with auto-login."""
    # Register a new user with auto-login
    user, tokens = register_user(
        username="newuser",
        email="new@example.com",
        password="Password123!",
        auto_login=True,
        ip_address="127.0.0.1",
        user_agent="test-agent",
        is_test_user=True
    )
    
    # Verify user was created
    assert user.id is not None
    
    # Verify tokens were returned
    assert tokens is not None
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    
    # Verify authentication attempt was recorded
    auth_attempt = db_session.query(AuthAttempt).filter_by(user_id=user.id).first()
    assert auth_attempt is not None
    assert auth_attempt.result == AuthAttemptResult.SUCCESS


def test_register_user_already_exists(test_user, db_session):
    """Test registration with existing username."""
    # Attempt to register with existing username
    with pytest.raises(UserExistsError):
        register_user(
            username=test_user.username,
            email="different@example.com",
            password="Password123!"
        )
    
    # Attempt to register with existing email
    with pytest.raises(UserExistsError):
        register_user(
            username="different",
            email=test_user.email,
            password="Password123!"
        )


def test_register_user_auto_login_without_ip(db_session):
    """Test auto-login without IP address."""
    # Attempt to register with auto-login but no IP
    with pytest.raises(ValueError):
        register_user(
            username="newuser",
            email="new@example.com",
            password="Password123!",
            auto_login=True
        )


def test_logout_user(user_tokens, db_session):
    """Test user logout."""
    # Logout user
    token = user_tokens["access_token"]
    result = logout_user(token)
    
    # Verify logout was successful
    assert result is True
    
    # Verify token was revoked in database
    token_id = db_session.query(Token).filter_by(status=TokenStatus.REVOKED).first().token_id
    assert token_id is not None


def test_logout_user_invalid_token(db_session):
    """Test logout with invalid token."""
    # Attempt to logout with invalid token
    result = logout_user("invalid.token")
    
    # Verify logout failed
    assert result is False


def test_logout_user_all_devices(test_user, user_tokens, db_session):
    """Test logging out from all devices."""
    # Logout from all devices
    count = logout_user_all_devices(test_user.id)
    
    # Verify all tokens were revoked
    assert count == 2
    
    # Verify tokens were revoked in database
    revoked_count = db_session.query(Token).filter_by(
        user_id=test_user.id,
        status=TokenStatus.REVOKED
    ).count()
    assert revoked_count == 2


def test_logout_user_all_devices_with_exclude(test_user, user_tokens, db_session):
    """Test logging out from all devices except current."""
    # Get token ID to exclude
    token = user_tokens["access_token"]
    token_data = jwt.decode(
        token,
        options={"verify_signature": False}
    )
    token_id = token_data["jti"]
    
    # Logout from all devices except current
    count = logout_user_all_devices(test_user.id, token_id)
    
    # Verify one token was revoked
    assert count == 1
    
    # Verify the excluded token is still active
    active_token = db_session.query(Token).filter_by(
        user_id=test_user.id,
        status=TokenStatus.ACTIVE
    ).first()
    assert active_token is not None
    assert active_token.token_id == token_id


def test_change_password(test_user, db_session):
    """Test changing a user's password."""
    # Change password
    result = change_password(
        test_user.id,
        "password123",
        "NewPassword123!"
    )
    
    # Verify password change was successful
    assert result is True
    
    # Verify password was updated
    db_session.refresh(test_user)
    assert test_user.verify_password("NewPassword123!")
    assert not test_user.verify_password("password123")


def test_change_password_user_not_found(db_session):
    """Test changing password for non-existent user."""
    # Attempt to change password for non-existent user
    with pytest.raises(UserNotFoundError):
        change_password(
            999,
            "password123",
            "NewPassword123!"
        )


def test_change_password_invalid_current(test_user, db_session):
    """Test changing password with invalid current password."""
    # Attempt to change password with wrong current password
    with pytest.raises(InvalidCredentialsError):
        change_password(
            test_user.id,
            "wrongpassword",
            "NewPassword123!"
        )


def test_authentication_manager_init():
    """Test initializing the authentication manager."""
    # Initialize with no session
    auth_manager = AuthenticationManager()
    assert auth_manager.session is None
    
    # Initialize with session
    session = "test_session"
    auth_manager = AuthenticationManager(session)
    assert auth_manager.session == session


def test_authentication_manager_session_context():
    """Test the session context manager."""
    # Test with provided session
    session = "test_session"
    auth_manager = AuthenticationManager(session)
    with auth_manager._get_session_context() as s:
        assert s == session
