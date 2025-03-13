"""
SQLAlchemy models for the Authentication Core Component.

This module defines the data models for users, tokens, and authentication attempts
used by the Authentication Core Component.
"""
import datetime
import enum
import uuid
from typing import List, Optional

from passlib.context import CryptContext
from sqlalchemy import (Boolean, Column, DateTime, Enum, ForeignKey, Integer,
                        String, Text)
from sqlalchemy.orm import relationship

from auth_core.database import Base

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserRole(enum.Enum):
    """User role enumeration."""
    USER = "user"
    ADMIN = "admin"


class User(Base):
    """
    User model for authentication.
    
    Stores user credentials with secure password hashing.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    # Relationships
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    auth_attempts = relationship("AuthAttempt", back_populates="user", cascade="all, delete-orphan")

    @property
    def is_admin(self) -> bool:
        """Check if the user has admin role."""
        return self.role == UserRole.ADMIN

    def set_password(self, password: str) -> None:
        """
        Hash and set the user password.
        
        Args:
            password: Plain text password to hash and store.
        """
        self.hashed_password = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        """
        Verify a password against the stored hash.
        
        Args:
            password: Plain text password to verify.
            
        Returns:
            True if the password matches, False otherwise.
        """
        return pwd_context.verify(password, self.hashed_password)

    def __repr__(self) -> str:
        """String representation of the User object."""
        return f"<User(id={self.id}, username={self.username}, email={self.email})>"


class TokenType(enum.Enum):
    """Token type enumeration."""
    ACCESS = "access"
    REFRESH = "refresh"


class TokenStatus(enum.Enum):
    """Token status enumeration."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Token(Base):
    """
    Token model for JWT token tracking and blacklisting.
    
    Tracks JWT tokens issued to users and their status.
    """
    __tablename__ = "tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_id = Column(String(36), unique=True, index=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_type = Column(Enum(TokenType), nullable=False)
    status = Column(Enum(TokenStatus), default=TokenStatus.ACTIVE, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="tokens")

    @property
    def is_active(self) -> bool:
        """Check if the token is active."""
        return (
            self.status == TokenStatus.ACTIVE and
            self.expires_at > datetime.datetime.utcnow()
        )

    def revoke(self) -> None:
        """Revoke the token."""
        self.status = TokenStatus.REVOKED
        self.revoked_at = datetime.datetime.utcnow()

    def __repr__(self) -> str:
        """String representation of the Token object."""
        return f"<Token(id={self.id}, user_id={self.user_id}, type={self.token_type.value}, status={self.status.value})>"


class AuthAttemptResult(enum.Enum):
    """Authentication attempt result enumeration."""
    SUCCESS = "success"
    FAILURE = "failure"


class AuthAttempt(Base):
    """
    Authentication attempt model for tracking login attempts.
    
    Used for brute force attack prevention by tracking failed login attempts.
    """
    __tablename__ = "auth_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    ip_address = Column(String(45), nullable=False, index=True)  # IPv6 can be up to 45 chars
    user_agent = Column(Text, nullable=True)
    username_attempt = Column(String(50), nullable=True)
    result = Column(Enum(AuthAttemptResult), nullable=False)
    attempt_time = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="auth_attempts")

    @classmethod
    def get_recent_failures(cls, session, ip_address: str, minutes: int = 30, username: Optional[str] = None) -> List["AuthAttempt"]:
        """
        Get recent failed authentication attempts from an IP address.
        
        Args:
            session: Database session.
            ip_address: IP address to check.
            minutes: Time window in minutes to check for failures.
            username: Optional username to filter attempts.
            
        Returns:
            List of failed authentication attempts.
        """
        cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes)
        query = session.query(cls).filter(
            cls.ip_address == ip_address,
            cls.result == AuthAttemptResult.FAILURE,
            cls.attempt_time >= cutoff_time
        )
        
        if username:
            query = query.filter(cls.username_attempt == username)
            
        return query.all()

    def __repr__(self) -> str:
        """String representation of the AuthAttempt object."""
        return f"<AuthAttempt(id={self.id}, user_id={self.user_id}, ip={self.ip_address}, result={self.result.value})>"