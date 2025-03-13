"""
Tests for the API endpoints.

This module tests the FastAPI endpoints for authentication, token validation,
and user management provided by the auth_core.api module.
"""
import json
from unittest.mock import patch

import pytest
from fastapi import status

from auth_core.models import AuthAttempt, AuthAttemptResult, Token, TokenStatus, User


def test_login_success(client, test_user):
    """Test successful login."""
    # Login request
    response = client.post(
        "/auth/login",
        json={
            "username": test_user.username,
            "password": "password123"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"


def test_login_with_email(client, test_user):
    """Test login with email."""
    # Login request with email
    response = client.post(
        "/auth/login",
        json={
            "username": test_user.email,
            "password": "password123"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data


def test_login_user_not_found(client):
    """Test login with non-existent user."""
    # Login request with non-existent user
    response = client.post(
        "/auth/login",
        json={
            "username": "nonexistent",
            "password": "password123"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_404_NOT_FOUND
    data = response.json()
    assert "detail" in data
    assert "User not found" in data["detail"]


def test_login_invalid_password(client, test_user):
    """Test login with invalid password."""
    # Login request with wrong password
    response = client.post(
        "/auth/login",
        json={
            "username": test_user.username,
            "password": "wrongpassword"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert "detail" in data
    assert "Invalid credentials" in data["detail"]


def test_login_inactive_user(client, inactive_user):
    """Test login with inactive user."""
    # Login request with inactive user
    response = client.post(
        "/auth/login",
        json={
            "username": inactive_user.username,
            "password": "password123"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_404_NOT_FOUND
    data = response.json()
    assert "detail" in data
    assert "User not found" in data["detail"]


def test_login_account_locked(client, test_user, db_session):
    """Test login with locked account."""
    # Create MAX_LOGIN_ATTEMPTS failed attempts
    for i in range(5):  # Using 5 as MAX_LOGIN_ATTEMPTS
        auth_attempt = AuthAttempt(
            user_id=test_user.id,
            ip_address="127.0.0.1",
            result=AuthAttemptResult.FAILURE
        )
        db_session.add(auth_attempt)
    db_session.commit()
    
    # Login request
    response = client.post(
        "/auth/login",
        json={
            "username": test_user.username,
            "password": "password123"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_403_FORBIDDEN
    data = response.json()
    assert "detail" in data
    assert "locked" in data["detail"].lower()


def test_register_success(client):
    """Test successful registration."""
    # Registration request
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "Password123!",
            "auto_login": False
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "message" in data
    assert "User registered successfully" in data["message"]
    assert "details" in data
    assert data["details"]["username"] == "newuser"
    assert data["details"]["email"] == "new@example.com"


def test_register_with_auto_login(client):
    """Test registration with auto-login."""
    # Registration request with auto-login
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "Password123!",
            "auto_login": True
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"


def test_register_user_exists(client, test_user):
    """Test registration with existing username."""
    # Registration request with existing username
    response = client.post(
        "/auth/register",
        json={
            "username": test_user.username,
            "email": "different@example.com",
            "password": "Password123!"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_409_CONFLICT
    data = response.json()
    assert "detail" in data
    assert "already exists" in data["detail"]
    
    # Registration request with existing email
    response = client.post(
        "/auth/register",
        json={
            "username": "different",
            "email": test_user.email,
            "password": "Password123!"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_409_CONFLICT
    data = response.json()
    assert "detail" in data
    assert "already exists" in data["detail"]


def test_refresh_token(client, user_tokens):
    """Test refreshing an access token."""
    # Refresh request
    response = client.post(
        "/auth/refresh",
        json={
            "refresh_token": user_tokens["refresh_token"]
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"


def test_refresh_token_expired(client):
    """Test refreshing with an expired token."""
    # Create an expired token
    expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidHlwZSI6InJlZnJlc2giLCJleHAiOjE1MTYyMzkwMjJ9.signature"
    
    # Refresh request with expired token
    response = client.post(
        "/auth/refresh",
        json={
            "refresh_token": expired_token
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert "detail" in data


def test_validate_token(client, user_tokens):
    """Test validating a token."""
    # Validation request
    response = client.post(
        "/auth/validate",
        json={
            "token": user_tokens["access_token"]
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "valid" in data
    assert data["valid"] is True
    assert "user_id" in data
    assert "username" in data
    assert "token_type" in data
    assert data["token_type"] == "access"
    assert "expires_at" in data


def test_validate_token_with_type(client, user_tokens):
    """Test validating a token with expected type."""
    # Validation request with expected type
    response = client.post(
        "/auth/validate",
        json={
            "token": user_tokens["access_token"],
            "token_type": "access"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["valid"] is True
    
    # Validation request with wrong expected type
    response = client.post(
        "/auth/validate",
        json={
            "token": user_tokens["access_token"],
            "token_type": "refresh"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["valid"] is False


def test_validate_invalid_token(client):
    """Test validating an invalid token."""
    # Validation request with invalid token
    response = client.post(
        "/auth/validate",
        json={
            "token": "invalid.token"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["valid"] is False
    assert data["user_id"] is None
    assert data["username"] is None
    assert data["token_type"] is None
    assert data["expires_at"] is None


def test_logout(client, user_tokens, db_session):
    """Test user logout."""
    # Logout request
    response = client.post(
        "/auth/logout",
        json={
            "token": user_tokens["access_token"],
            "all_devices": False
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "message" in data
    assert "Logged out successfully" in data["message"]
    
    # Verify token was revoked
    token_id = db_session.query(Token).filter_by(status=TokenStatus.REVOKED).first().token_id
    assert token_id is not None


def test_logout_all_devices(client, user_tokens, test_user, db_session):
    """Test logging out from all devices."""
    # Logout request for all devices
    response = client.post(
        "/auth/logout",
        json={
            "token": user_tokens["access_token"],
            "all_devices": True
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "message" in data
    assert "Logged out from all devices" in data["message"]
    assert "details" in data
    assert "tokens_revoked" in data["details"]
    assert data["details"]["tokens_revoked"] == 2
    
    # Verify all tokens were revoked
    revoked_count = db_session.query(Token).filter_by(
        user_id=test_user.id,
        status=TokenStatus.REVOKED
    ).count()
    assert revoked_count == 2


def test_logout_invalid_token(client):
    """Test logout with invalid token."""
    # Logout request with invalid token
    response = client.post(
        "/auth/logout",
        json={
            "token": "invalid.token",
            "all_devices": False
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert "detail" in data


def test_change_password(client, user_tokens, test_user, db_session):
    """Test changing a user's password."""
    # Change password request
    response = client.post(
        "/auth/password",
        headers={"Authorization": f"Bearer {user_tokens['access_token']}"},
        json={
            "current_password": "password123",
            "new_password": "NewPassword123!"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "message" in data
    assert "Password changed successfully" in data["message"]
    
    # Verify password was updated
    db_session.refresh(test_user)
    assert test_user.verify_password("NewPassword123!")
    assert not test_user.verify_password("password123")


def test_change_password_invalid_current(client, user_tokens):
    """Test changing password with invalid current password."""
    # Change password request with wrong current password
    response = client.post(
        "/auth/password",
        headers={"Authorization": f"Bearer {user_tokens['access_token']}"},
        json={
            "current_password": "wrongpassword",
            "new_password": "NewPassword123!"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert "detail" in data
    assert "Current password is incorrect" in data["detail"]


def test_change_password_no_auth(client):
    """Test changing password without authentication."""
    # Change password request without auth header
    response = client.post(
        "/auth/password",
        json={
            "current_password": "password123",
            "new_password": "NewPassword123!"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert "detail" in data


def test_change_password_invalid_token(client):
    """Test changing password with invalid token."""
    # Change password request with invalid token
    response = client.post(
        "/auth/password",
        headers={"Authorization": "Bearer invalid.token"},
        json={
            "current_password": "password123",
            "new_password": "NewPassword123!"
        }
    )
    
    # Verify response
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    data = response.json()
    assert "detail" in data


def test_health_check(client):
    """Test health check endpoint."""
    # Health check request
    response = client.get("/health")
    
    # Verify response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"
    assert "version" in data