"""
Test fixtures for the Authentication Core Component.

This module provides pytest fixtures for database, application, and authentication
testing, including in-memory database setup, test client, and test users.
"""
import os
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth_core.database import Base, get_session
from auth_core.models import User, UserRole, AuthAttempt
from auth_core.config import settings
from auth_core.token import create_token_pair
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
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def clear_auth_attempts(db_session):
    """Clear all authentication attempts before each test."""
    db_session.query(AuthAttempt).delete()
    db_session.commit()
    return True


@pytest.fixture(scope="function", autouse=True)
def patch_lockout_checks():
    """Patch the lockout checks to bypass them during tests."""
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
def client(db_engine, db_session, clear_auth_attempts):
    """Create a FastAPI test client with a test database."""
    # Override the get_session dependency
    def override_get_session():
        try:
            yield db_session
        finally:
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
def user_tokens(test_user, db_session):
    """Create tokens for a test user."""
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
