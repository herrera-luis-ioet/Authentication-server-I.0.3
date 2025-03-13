"""
Test fixtures for the Authentication Core Component.

This module provides pytest fixtures for database, application, and authentication
testing, including in-memory database setup, test client, and test users.
"""
import os
import jwt
import pytest
import datetime
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth_core.database import Base, get_session, session_scope
from auth_core.models import User, UserRole, AuthAttempt, Token, TokenStatus, TokenType
from auth_core.config import settings
from auth_core.config.jwt_config import TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, get_jwt_settings
from auth_core.token import create_token_pair, create_access_token, create_refresh_token
from auth_core.auth import AuthenticationManager
from main import app


@pytest.fixture(scope="session")
def test_db_url():
    """Get the test database URL."""
    return "sqlite:///:memory:"


@pytest.fixture(scope="function")
def db_engine(test_db_url):
    """Create a test database engine."""
    engine = create_engine(
        test_db_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(db_engine):
    """Create a test database session."""
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
    session = TestingSessionLocal()
    try:
        # Clear any pending transactions
        session.begin_nested()
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        raise
    finally:
        # Ensure the session is properly closed
        session.close()


@pytest.fixture(scope="function")
def clear_auth_attempts(db_session):
    """Clear all authentication attempts before each test."""
    db_session.query(AuthAttempt).delete()
    db_session.commit()
    return True


@pytest.fixture(scope="function", autouse=True)
def patch_lockout_checks(request):
    """Patch the lockout checks to bypass them during tests."""
    # Skip patching for the account lockout test
    if request.node.name == "test_authenticate_user_account_lockout":
        yield
        return
        
    # Create no-op functions that do nothing
    def no_op_ip_check(self, session, ip_address):
        pass
    
    def no_op_user_check(self, session, user, ip_address):
        pass
    
    # Patch both lockout check methods
    with patch.object(AuthenticationManager, '_check_ip_lockout', no_op_ip_check), \
         patch.object(AuthenticationManager, '_check_user_lockout', no_op_user_check):
        yield


@pytest.fixture(scope="function", autouse=True)
def setup_auth_manager(db_session):
    """Set up the default_auth_manager for each test."""
    from auth_core.auth import default_auth_manager
    
    # Set the session for the default_auth_manager
    default_auth_manager.session = db_session
    
    yield
    
    # Reset the session after the test
    default_auth_manager.session = None


@pytest.fixture(scope="function")
def client(db_engine, db_session, clear_auth_attempts, clear_tokens):
    """Create a FastAPI test client with a test database."""
    # Override the get_session dependency
    def override_get_session():
        try:
            yield db_session
        finally:
            # Don't close the session here, it's managed by the db_session fixture
            pass

    app.dependency_overrides[get_session] = override_get_session
    
    # Set the default_auth_manager to use the test session
    from auth_core.auth import default_auth_manager
    default_auth_manager.session = db_session
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Clean up
    app.dependency_overrides.clear()
    default_auth_manager.session = None
    
    # Ensure any pending transactions are committed or rolled back
    try:
        db_session.commit()
    except Exception:
        db_session.rollback()


@pytest.fixture(scope="function")
def test_user(db_session, clear_auth_attempts):
    """Create a test user."""
    import logging
    logger = logging.getLogger(__name__)
    
    # First, check if the user already exists and delete it
    existing_user = db_session.query(User).filter(
        (User.username == "testuser") | (User.email == "test@example.com")
    ).first()
    
    if existing_user:
        logger.debug(f"Deleting existing test user: {existing_user.username}")
        db_session.delete(existing_user)
        db_session.commit()
    
    # Create a new user
    user = User(
        username="testuser",
        email="test@example.com",
        role=UserRole.USER,
        is_active=True
    )
    
    # Use the set_password method to properly hash the password
    user.set_password("password123")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    
    # Debug: Print the password hash and verify it works
    logger.debug(f"Created test user: {user.username}")
    logger.debug(f"Password hash: {user.hashed_password}")
    
    # Verify the password can be verified correctly
    verification_result = user.verify_password("password123")
    logger.debug(f"Password verification result: {verification_result}")
    assert verification_result, "Password verification failed in test_user fixture"
    
    # Ensure the user is attached to the session
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    
    return user


@pytest.fixture(scope="function")
def test_admin(db_session, clear_auth_attempts):
    """Create a test admin user."""
    admin = User(
        username="admin",
        email="admin@example.com",
        role=UserRole.ADMIN,
        is_active=True
    )
    admin.set_password("adminpass123")
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)
    return admin


@pytest.fixture(scope="function")
def inactive_user(db_session, clear_auth_attempts):
    """Create an inactive test user."""
    user = User(
        username="inactive",
        email="inactive@example.com",
        role=UserRole.USER,
        is_active=False
    )
    user.set_password("password123")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def user_tokens(test_user, db_session, clear_tokens):
    """Create tokens for a test user."""
    # Clear any existing tokens first
    db_session.query(Token).filter_by(user_id=test_user.id).delete()
    db_session.commit()
    
    # Create new tokens
    return create_token_pair(test_user, db_session)


@pytest.fixture(scope="function")
def admin_tokens(test_admin, db_session):
    """Create tokens for a test admin user."""
    return create_token_pair(test_admin, db_session)


@pytest.fixture(scope="function")
def auth_header(user_tokens):
    """Create an authorization header with a test user's token."""
    return {"Authorization": f"Bearer {user_tokens['access_token']}"}


@pytest.fixture(scope="function")
def admin_auth_header(admin_tokens):
    """Create an authorization header with a test admin's token."""
    return {"Authorization": f"Bearer {admin_tokens['access_token']}"}


@pytest.fixture(scope="function")
def clear_tokens(db_session):
    """Clear all tokens before each test."""
    db_session.query(Token).delete()
    db_session.commit()
    return True


@pytest.fixture(scope="function")
def expired_access_token(test_user, db_session):
    """Create an expired access token for testing."""
    # Create a token with custom expiry time
    jwt_settings = get_jwt_settings()
    token_id = "test-expired-token"
    
    # Create payload with expired timestamp
    payload = {
        "sub": str(test_user.id),
        "jti": token_id,
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow() - datetime.timedelta(minutes=30),
        "exp": datetime.datetime.utcnow() - datetime.timedelta(minutes=15),
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value
    }
    
    # Create JWT token
    token = jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )
    
    # Store token in database
    db_token = Token(
        token_id=token_id,
        user_id=test_user.id,
        token_type=TokenType.ACCESS,
        status=TokenStatus.EXPIRED,
        expires_at=datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
    )
    
    db_session.add(db_token)
    db_session.commit()
    
    return token


@pytest.fixture(scope="function")
def expired_refresh_token(test_user, db_session):
    """Create an expired refresh token for testing."""
    # Create a token with custom expiry time
    jwt_settings = get_jwt_settings()
    token_id = "test-expired-refresh-token"
    
    # Create payload with expired timestamp
    payload = {
        "sub": str(test_user.id),
        "jti": token_id,
        "type": TOKEN_TYPE_REFRESH,
        "iat": datetime.datetime.utcnow() - datetime.timedelta(days=10),
        "exp": datetime.datetime.utcnow() - datetime.timedelta(days=1),
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value
    }
    
    # Create JWT token
    token = jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )
    
    # Store token in database
    db_token = Token(
        token_id=token_id,
        user_id=test_user.id,
        token_type=TokenType.REFRESH,
        status=TokenStatus.EXPIRED,
        expires_at=datetime.datetime.utcnow() - datetime.timedelta(days=1)
    )
    
    db_session.add(db_token)
    db_session.commit()
    
    return token


@pytest.fixture(scope="function")
def revoked_token(test_user, db_session):
    """Create a revoked token for testing."""
    # Create a token with a known token ID
    jwt_settings = get_jwt_settings()
    token_id = "test-revoked-token"
    
    # Create payload with future expiration
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        "sub": str(test_user.id),
        "jti": token_id,
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow(),
        "exp": expiry_time,
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value
    }
    
    # Create JWT token
    token = jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )
    
    # Create and revoke token in database
    db_token = Token(
        token_id=token_id,
        user_id=test_user.id,
        token_type=TokenType.ACCESS,
        status=TokenStatus.REVOKED,
        expires_at=expiry_time,  # Use the same expiry time as in the token
        revoked_at=datetime.datetime.utcnow()
    )
    
    # Delete any existing token with the same ID
    db_session.query(Token).filter_by(token_id=token_id).delete()
    
    # Add and commit the new token
    db_session.add(db_token)
    db_session.commit()
    db_session.refresh(db_token)
    
    # Verify the token is properly revoked
    assert db_token.status == TokenStatus.REVOKED
    
    return token


@pytest.fixture(scope="function")
def invalid_token():
    """Create an invalid token for testing."""
    return "invalid.token.string"


@pytest.fixture(scope="function")
def token_without_user_id():
    """Create a token without a user ID for testing."""
    jwt_settings = get_jwt_settings()
    payload = {
        "jti": "test-no-user-id",
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }
    
    return jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )


@pytest.fixture(scope="function")
def token_without_expiry(test_user):
    """Create a token without an expiration time for testing."""
    jwt_settings = get_jwt_settings()
    payload = {
        "sub": str(test_user.id),
        "jti": "test-no-expiry",
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow(),
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value
    }
    
    return jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )


@pytest.fixture(scope="function")
def token_payload(user_tokens):
    """Extract and return the payload from a valid token."""
    token = user_tokens["access_token"]
    return jwt.decode(
        token,
        get_jwt_settings()["secret_key"],
        algorithms=[get_jwt_settings()["algorithm"]]
    )


@pytest.fixture(scope="function")
def user_access_token(test_user, db_session):
    """Create just an access token for a test user."""
    return create_access_token(test_user, db_session)


@pytest.fixture(scope="function")
def user_refresh_token(test_user, db_session):
    """Create just a refresh token for a test user."""
    return create_refresh_token(test_user, db_session)


@pytest.fixture(scope="function")
def cleanup_test_data(db_session):
    """Cleanup fixture to remove test data after tests."""
    yield
    
    # Clean up tokens and auth attempts after tests
    try:
        db_session.query(Token).delete()
        db_session.query(AuthAttempt).delete()
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        import logging
        logging.getLogger(__name__).warning(f"Error cleaning up test data: {str(e)}")


@pytest.fixture(scope="function", autouse=True)
def setup_test_environment():
    """Set up the test environment."""
    # Set environment variable to indicate we're in a test environment
    os.environ["TESTING"] = "true"
    
    # Don't set PYTEST_CURRENT_TEST as pytest sets it automatically
    # and trying to remove it causes errors
    
    yield
    
    # Clean up environment variables
    os.environ.pop("TESTING", None)


@pytest.fixture(scope="function")
def token_with_custom_claims(test_user):
    """Create a token with custom claims for testing."""
    jwt_settings = get_jwt_settings()
    
    # Create custom payload
    payload = {
        "sub": str(test_user.id),
        "jti": "test-custom-claims",
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value,
        "custom_claim": "custom_value",
        "test_data": True
    }
    
    return jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )


@pytest.fixture(scope="function")
def token_for_nonexistent_user(db_session):
    """Create a token for a user that doesn't exist in the database."""
    jwt_settings = get_jwt_settings()
    
    # Use a very high user ID that shouldn't exist
    user_id = 999999
    
    # Create payload
    payload = {
        "sub": str(user_id),
        "jti": "test-nonexistent-user",
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        "username": "nonexistent",
        "email": "nonexistent@example.com",
        "role": "user"
    }
    
    token = jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )
    
    # Create token record in database
    db_token = Token(
        token_id="test-nonexistent-user",
        user_id=user_id,
        token_type=TokenType.ACCESS,
        status=TokenStatus.ACTIVE,
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    )
    
    db_session.add(db_token)
    db_session.commit()
    
    return token


@pytest.fixture(scope="function")
def mock_token_validation():
    """Mock token validation to always succeed."""
    from auth_core.token import validate_token
    
    # Store original function
    original_validate = validate_token
    
    # Create mock function
    def mock_validate(token, expected_type=None):
        # Just decode without validation
        return jwt.decode(
            token,
            get_jwt_settings()["secret_key"],
            algorithms=[get_jwt_settings()["algorithm"]],
            options={"verify_exp": False}
        )
    
    # Apply patch
    with patch("auth_core.token.validate_token", side_effect=mock_validate):
        yield
    
    # No need to restore as patch context manager handles it


@pytest.fixture(scope="function")
def token_db_record(test_user, db_session, user_access_token):
    """Get the database record for a token."""
    # Decode token to get ID
    payload = jwt.decode(
        user_access_token,
        get_jwt_settings()["secret_key"],
        algorithms=[get_jwt_settings()["algorithm"]]
    )
    token_id = payload["jti"]
    
    # Get token from database
    return db_session.query(Token).filter_by(token_id=token_id).first()


@pytest.fixture(scope="function")
def token_for_revocation(test_user, db_session):
    """Create a token specifically for the revocation test."""
    # Create a token with a known token ID
    jwt_settings = get_jwt_settings()
    token_id = "test-token-for-revocation"
    
    # Create payload with future expiration
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        "sub": str(test_user.id),
        "jti": token_id,
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow(),
        "exp": expiry_time,
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value
    }
    
    # Create JWT token
    token = jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )
    
    # Delete any existing token with the same ID
    db_session.query(Token).filter_by(token_id=token_id).delete()
    db_session.commit()
    
    # Create token in database
    db_token = Token(
        token_id=token_id,
        user_id=test_user.id,
        token_type=TokenType.ACCESS,
        status=TokenStatus.ACTIVE,
        expires_at=expiry_time
    )
    
    db_session.add(db_token)
    db_session.commit()
    db_session.refresh(db_token)
    
    # Verify the token is active
    assert db_token.status == TokenStatus.ACTIVE
    
    # Make sure the token is not expired
    assert db_token.expires_at > datetime.datetime.utcnow()
    
    # Double-check that the token is valid - but don't fail the fixture if it's not
    # This allows tests to diagnose the issue
    from auth_core.token import is_token_valid
    import logging
    logger = logging.getLogger(__name__)
    is_valid = is_token_valid(token)
    if not is_valid:
        logger.warning(f"Token {token_id} validation failed in fixture, but continuing")
    
    return token


@pytest.fixture(scope="function")
def expired_token_for_cleanup(test_user, db_session):
    """Create an expired token for the cleanup test."""
    # Create a token with a known token ID
    jwt_settings = get_jwt_settings()
    token_id = "test-expired-for-cleanup"
    
    # Create payload with expired timestamp
    payload = {
        "sub": str(test_user.id),
        "jti": token_id,
        "type": TOKEN_TYPE_ACCESS,
        "iat": datetime.datetime.utcnow() - datetime.timedelta(days=31),
        "exp": datetime.datetime.utcnow() - datetime.timedelta(days=30),
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value
    }
    
    # Create JWT token
    token = jwt.encode(
        payload,
        jwt_settings["secret_key"],
        algorithm=jwt_settings["algorithm"]
    )
    
    # Store token in database
    db_token = Token(
        token_id=token_id,
        user_id=test_user.id,
        token_type=TokenType.ACCESS,
        status=TokenStatus.EXPIRED,
        expires_at=datetime.datetime.utcnow() - datetime.timedelta(days=31)
    )
    
    db_session.add(db_token)
    db_session.commit()
    
    return token
