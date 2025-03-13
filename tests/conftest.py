"""
Test fixtures for the Authentication Core Component.

This module provides pytest fixtures for database, application, and authentication
testing, including in-memory database setup, test client, and test users.
"""
import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth_core.database import Base, get_session
from auth_core.models import User, UserRole
from auth_core.config import settings
from auth_core.token import create_token_pair
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
def client(db_engine, db_session):
    """Create a FastAPI test client with a test database."""
    # Override the get_session dependency
    def override_get_session():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_session] = override_get_session
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Clean up
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def test_user(db_session):
    """Create a test user."""
    user = User(
        username="testuser",
        email="test@example.com",
        role=UserRole.USER,
        is_active=True
    )
    # Explicitly set the password using the pwd_context from models
    from auth_core.models import pwd_context
    user.hashed_password = pwd_context.hash("password123")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    # Verify the password can be verified correctly
    assert user.verify_password("password123")
    return user


@pytest.fixture(scope="function")
def test_admin(db_session):
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
def inactive_user(db_session):
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
