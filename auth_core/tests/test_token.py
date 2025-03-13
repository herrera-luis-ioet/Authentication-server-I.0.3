"""
Tests for the JWT token management module.
"""
import datetime
import time
import unittest
from unittest.mock import patch

import jwt
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auth_core.database import Base
from auth_core.models import User, TokenType, TokenStatus
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
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)


class TestTokenManagement(unittest.TestCase):
    """Test cases for JWT token management functionality."""

    def setUp(self):
        """Set up test database and create a test user."""
        # Create in-memory SQLite database for testing
        self.engine = create_engine("sqlite:///:memory:")
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        
        # Create a test session
        self.session = self.SessionLocal()
        
        # Create a test user
        self.test_user = User(
            username="testuser",
            email="test@example.com",
        )
        self.test_user.set_password("password123")
        
        self.session.add(self.test_user)
        self.session.commit()
        
        # Refresh the user to get the ID
        self.session.refresh(self.test_user)

    def tearDown(self):
        """Clean up after tests."""
        self.session.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_create_access_token(self):
        """Test creating an access token."""
        token = create_access_token(self.test_user, self.session)
        
        # Verify token is a string
        self.assertIsInstance(token, str)
        
        # Decode token and verify claims
        payload = get_token_data(token)
        self.assertEqual(payload["sub"], str(self.test_user.id))
        self.assertEqual(payload["type"], "access")
        self.assertEqual(payload["username"], self.test_user.username)
        
        # Verify token is stored in database
        db_token = self.session.query(User).filter_by(id=self.test_user.id).first().tokens[0]
        self.assertEqual(db_token.token_type, TokenType.ACCESS)
        self.assertEqual(db_token.status, TokenStatus.ACTIVE)

    def test_create_refresh_token(self):
        """Test creating a refresh token."""
        token = create_refresh_token(self.test_user, self.session)
        
        # Verify token is a string
        self.assertIsInstance(token, str)
        
        # Decode token and verify claims
        payload = get_token_data(token)
        self.assertEqual(payload["sub"], str(self.test_user.id))
        self.assertEqual(payload["type"], "refresh")
        
        # Verify token is stored in database
        db_token = self.session.query(User).filter_by(id=self.test_user.id).first().tokens[0]
        self.assertEqual(db_token.token_type, TokenType.REFRESH)
        self.assertEqual(db_token.status, TokenStatus.ACTIVE)

    def test_create_token_pair(self):
        """Test creating both access and refresh tokens."""
        tokens = create_token_pair(self.test_user, self.session)
        
        # Verify response structure
        self.assertIn("access_token", tokens)
        self.assertIn("refresh_token", tokens)
        self.assertIn("token_type", tokens)
        self.assertEqual(tokens["token_type"], "bearer")
        
        # Verify both tokens are valid
        access_payload = get_token_data(tokens["access_token"])
        refresh_payload = get_token_data(tokens["refresh_token"])
        
        self.assertEqual(access_payload["type"], "access")
        self.assertEqual(refresh_payload["type"], "refresh")

    def test_validate_token(self):
        """Test token validation."""
        token = create_access_token(self.test_user, self.session)
        
        # Validate token
        payload = validate_token(token)
        self.assertEqual(payload["sub"], str(self.test_user.id))
        
        # Validate with expected type
        payload = validate_token(token, expected_type="access")
        self.assertEqual(payload["type"], "access")
        
        # Test with wrong expected type
        with self.assertRaises(TokenInvalidError):
            validate_token(token, expected_type="refresh")

    def test_refresh_access_token(self):
        """Test refreshing an access token."""
        refresh_token = create_refresh_token(self.test_user, self.session)
        
        # Refresh the access token
        result = refresh_access_token(refresh_token)
        
        # Verify response structure
        self.assertIn("access_token", result)
        self.assertIn("token_type", result)
        self.assertEqual(result["token_type"], "bearer")
        
        # Verify the new access token is valid
        payload = validate_token(result["access_token"], expected_type="access")
        self.assertEqual(payload["sub"], str(self.test_user.id))

    def test_revoke_token(self):
        """Test revoking a token."""
        token = create_access_token(self.test_user, self.session)
        
        # Verify token is valid before revocation
        self.assertTrue(is_token_valid(token))
        
        # Revoke the token
        result = revoke_token(token)
        self.assertTrue(result)
        
        # Verify token is no longer valid
        self.assertFalse(is_token_valid(token))
        
        # Verify token status in database
        token_id = get_token_data(token)["jti"]
        db_token = self.session.query(User).filter_by(id=self.test_user.id).first().tokens[0]
        self.assertEqual(db_token.status, TokenStatus.REVOKED)

    def test_revoke_all_user_tokens(self):
        """Test revoking all tokens for a user."""
        # Create multiple tokens
        token1 = create_access_token(self.test_user, self.session)
        token2 = create_refresh_token(self.test_user, self.session)
        
        # Revoke all tokens
        count = revoke_all_user_tokens(self.test_user.id)
        self.assertEqual(count, 2)
        
        # Verify all tokens are revoked
        self.assertFalse(is_token_valid(token1))
        self.assertFalse(is_token_valid(token2))

    def test_get_user_id_from_token(self):
        """Test extracting user ID from a token."""
        token = create_access_token(self.test_user, self.session)
        
        # Get user ID
        user_id = get_user_id_from_token(token)
        self.assertEqual(user_id, self.test_user.id)

    def test_expired_token(self):
        """Test handling of expired tokens."""
        # Create a token that expires in 1 second
        with patch("auth_core.token.get_token_expiry") as mock_expiry:
            mock_expiry.return_value = datetime.timedelta(seconds=1)
            token = create_access_token(self.test_user, self.session)
        
        # Wait for token to expire
        time.sleep(2)
        
        # Verify token is expired
        with self.assertRaises(TokenExpiredError):
            validate_token(token)
        
        # Verify is_token_valid returns False
        self.assertFalse(is_token_valid(token))

    def test_clean_expired_tokens(self):
        """Test cleaning expired tokens from the database."""
        # Create a token that expires immediately
        with patch("auth_core.token.get_token_expiry") as mock_expiry:
            mock_expiry.return_value = datetime.timedelta(seconds=-1)
            token = create_access_token(self.test_user, self.session)
        
        # Clean expired tokens
        count = clean_expired_tokens(days_old=0)
        self.assertEqual(count, 1)
        
        # Verify token is removed from database
        tokens = self.session.query(User).filter_by(id=self.test_user.id).first().tokens
        self.assertEqual(len(tokens), 0)


if __name__ == "__main__":
    unittest.main()