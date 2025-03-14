#!/usr/bin/env python3
"""
Simple script to test token validation with a revoked token.
"""
import os
import sys
import datetime
import jwt
from sqlalchemy.orm import Session

# Set up the environment
os.environ["TESTING"] = "true"

# Import the necessary modules
from auth_core.database import session_scope
from auth_core.models import Token, TokenStatus, TokenType, User, UserRole
from auth_core.config.jwt_config import TOKEN_TYPE_ACCESS, get_jwt_settings
from auth_core.token import validate_token, TokenRevokedError

def main():
    """Main function to test token validation with a revoked token."""
    print("Testing token validation with a revoked token...")
    
    # Create a token with a known token ID
    jwt_settings = get_jwt_settings()
    token_id = "test-revoked-token"
    
    # Create payload with future expiration
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    payload = {
        "sub": "1",  # User ID 1
        "jti": token_id,
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow(),
        "exp": expiry_time,
        "username": "testuser",
        "email": "test@example.com",
        "role": "user"
    }
    
    # Create JWT token
    token = jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )
    
    print(f"Created token: {token}")
    
    with session_scope() as session:
        # Check if user exists, create if not
        user = session.query(User).filter_by(id=1).first()
        if not user:
            print("Creating test user...")
            user = User(
                id=1,
                username="testuser",
                email="test@example.com",
                role=UserRole.USER,
                is_active=True,
                hashed_password="test_password_hash"
            )
            session.add(user)
            session.flush()
        
        # Delete any existing token with the same ID
        session.query(Token).filter_by(token_id=token_id).delete()
        session.commit()
        
        # Create and revoke token in database
        db_token = Token(
            token_id=token_id,
            user_id=1,
            token_type=TokenType.ACCESS,
            status=TokenStatus.REVOKED,
            expires_at=expiry_time,
            revoked_at=datetime.datetime.utcnow()
        )
        
        # Add and commit the new token
        session.add(db_token)
        session.commit()
        session.refresh(db_token)
        
        # Verify the token is properly revoked
        assert db_token.status == TokenStatus.REVOKED
        print(f"Token status in database: {db_token.status}")
        
        # Now test the validate_token function
        try:
            print("Validating token...")
            validate_token(token)
            print("ERROR: Expected TokenRevokedError but no exception was raised")
            return 1
        except TokenRevokedError:
            print("SUCCESS: TokenRevokedError was raised as expected")
            return 0
        except Exception as e:
            print(f"ERROR: Expected TokenRevokedError but got {type(e).__name__}: {str(e)}")
            return 1

if __name__ == "__main__":
    sys.exit(main())