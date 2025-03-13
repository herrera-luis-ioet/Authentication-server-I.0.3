"""
Security utilities for the Authentication Core Component.

This module provides security-related functionality including password hashing,
password strength validation, rate limiting, and other security utilities.
"""
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Pattern, Tuple, Union

import bcrypt
from passlib.context import CryptContext

# Configure logging
logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security constants
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 30
PASSWORD_RESET_TOKEN_EXPIRY_HOURS = 24

# Rate limiting constants
RATE_LIMIT_DEFAULT_WINDOW = 60  # 1 minute window
RATE_LIMIT_DEFAULT_MAX_REQUESTS = 60  # 60 requests per minute


class PasswordError(Exception):
    """Base exception for password-related errors."""
    pass


class WeakPasswordError(PasswordError):
    """Exception raised when a password does not meet strength requirements."""
    pass


class RateLimitExceededError(Exception):
    """Exception raised when rate limit is exceeded."""
    pass


class PasswordValidator:
    """
    Password strength validator.
    
    Validates passwords against configurable strength requirements.
    """
    
    def __init__(
        self,
        min_length: int = MIN_PASSWORD_LENGTH,
        max_length: int = MAX_PASSWORD_LENGTH,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digit: bool = True,
        require_special: bool = True,
        disallow_common: bool = True
    ):
        """
        Initialize the password validator with configurable requirements.
        
        Args:
            min_length: Minimum password length.
            max_length: Maximum password length.
            require_uppercase: Whether to require uppercase letters.
            require_lowercase: Whether to require lowercase letters.
            require_digit: Whether to require at least one digit.
            require_special: Whether to require at least one special character.
            disallow_common: Whether to disallow common passwords.
        """
        self.min_length = min_length
        self.max_length = max_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special
        self.disallow_common = disallow_common
        
        # Common passwords to disallow (this is a small sample, should be expanded in production)
        self.common_passwords = {
            "password", "123456", "qwerty", "admin", "welcome", 
            "123456789", "12345678", "abc123", "password1", "admin123"
        }
        
        # Regex patterns for validation
        self.uppercase_pattern: Pattern = re.compile(r"[A-Z]")
        self.lowercase_pattern: Pattern = re.compile(r"[a-z]")
        self.digit_pattern: Pattern = re.compile(r"\d")
        self.special_pattern: Pattern = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]")

    # PUBLIC_INTERFACE
    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate a password against the configured requirements.
        
        Args:
            password: Password to validate.
            
        Returns:
            Tuple containing:
                - Boolean indicating if the password is valid.
                - List of validation error messages (empty if valid).
        """
        errors = []
        
        # Check length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long.")
        
        if len(password) > self.max_length:
            errors.append(f"Password must be at most {self.max_length} characters long.")
        
        # Check character requirements
        if self.require_uppercase and not self.uppercase_pattern.search(password):
            errors.append("Password must contain at least one uppercase letter.")
        
        if self.require_lowercase and not self.lowercase_pattern.search(password):
            errors.append("Password must contain at least one lowercase letter.")
        
        if self.require_digit and not self.digit_pattern.search(password):
            errors.append("Password must contain at least one digit.")
        
        if self.require_special and not self.special_pattern.search(password):
            errors.append("Password must contain at least one special character.")
        
        # Check for common passwords
        if self.disallow_common and password.lower() in self.common_passwords:
            errors.append("Password is too common and easily guessable.")
        
        return len(errors) == 0, errors

    # PUBLIC_INTERFACE
    def validate_or_raise(self, password: str) -> None:
        """
        Validate a password and raise an exception if it's invalid.
        
        Args:
            password: Password to validate.
            
        Raises:
            WeakPasswordError: If the password does not meet the requirements.
        """
        is_valid, errors = self.validate(password)
        if not is_valid:
            raise WeakPasswordError("\n".join(errors))


class PasswordManager:
    """
    Password management utilities.
    
    Provides functionality for hashing and verifying passwords.
    """
    
    def __init__(self, validator: Optional[PasswordValidator] = None):
        """
        Initialize the password manager.
        
        Args:
            validator: Optional password validator for strength validation.
        """
        self.validator = validator or PasswordValidator()
    
    # PUBLIC_INTERFACE
    def hash_password(self, password: str, validate: bool = True) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: Plain text password to hash.
            validate: Whether to validate password strength before hashing.
            
        Returns:
            Hashed password string.
            
        Raises:
            WeakPasswordError: If validate is True and the password is weak.
        """
        if validate:
            self.validator.validate_or_raise(password)
        
        return pwd_context.hash(password)
    
    # PUBLIC_INTERFACE
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against a hash.
        
        Args:
            plain_password: Plain text password to verify.
            hashed_password: Hashed password to compare against.
            
        Returns:
            True if the password matches the hash, False otherwise.
        """
        return pwd_context.verify(plain_password, hashed_password)
    
    # PUBLIC_INTERFACE
    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if a password hash needs to be updated.
        
        This is useful when the hashing algorithm or parameters have changed.
        
        Args:
            hashed_password: Hashed password to check.
            
        Returns:
            True if the password should be rehashed, False otherwise.
        """
        return pwd_context.needs_update(hashed_password)


class RateLimiter:
    """
    Rate limiting implementation.
    
    Limits the number of requests from a specific source within a time window.
    """
    
    def __init__(
        self,
        window_seconds: int = RATE_LIMIT_DEFAULT_WINDOW,
        max_requests: int = RATE_LIMIT_DEFAULT_MAX_REQUESTS
    ):
        """
        Initialize the rate limiter.
        
        Args:
            window_seconds: Time window in seconds.
            max_requests: Maximum number of requests allowed in the window.
        """
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.request_records: Dict[str, List[float]] = {}
    
    # PUBLIC_INTERFACE
    def is_rate_limited(self, key: str) -> bool:
        """
        Check if a key is currently rate limited.
        
        Args:
            key: Identifier for the request source (e.g., IP address).
            
        Returns:
            True if the key is rate limited, False otherwise.
        """
        self._clean_old_requests(key)
        return len(self.request_records.get(key, [])) >= self.max_requests
    
    # PUBLIC_INTERFACE
    def add_request(self, key: str) -> bool:
        """
        Record a new request and check if rate limit is exceeded.
        
        Args:
            key: Identifier for the request source (e.g., IP address).
            
        Returns:
            True if the request is allowed, False if rate limited.
            
        Raises:
            RateLimitExceededError: If the rate limit is exceeded.
        """
        self._clean_old_requests(key)
        
        # Check if already rate limited
        if len(self.request_records.get(key, [])) >= self.max_requests:
            raise RateLimitExceededError(f"Rate limit exceeded for {key}")
        
        # Record the new request
        if key not in self.request_records:
            self.request_records[key] = []
        
        self.request_records[key].append(time.time())
        return True
    
    # PUBLIC_INTERFACE
    def get_remaining(self, key: str) -> int:
        """
        Get the number of remaining requests allowed for a key.
        
        Args:
            key: Identifier for the request source (e.g., IP address).
            
        Returns:
            Number of remaining requests allowed in the current window.
        """
        self._clean_old_requests(key)
        return max(0, self.max_requests - len(self.request_records.get(key, [])))
    
    # PUBLIC_INTERFACE
    def get_reset_time(self, key: str) -> Optional[float]:
        """
        Get the time when the rate limit will reset for a key.
        
        Args:
            key: Identifier for the request source (e.g., IP address).
            
        Returns:
            Timestamp when the rate limit will reset, or None if no requests.
        """
        if key not in self.request_records or not self.request_records[key]:
            return None
        
        oldest_request = min(self.request_records[key])
        return oldest_request + self.window_seconds
    
    def _clean_old_requests(self, key: str) -> None:
        """
        Remove requests that are outside the current time window.
        
        Args:
            key: Identifier for the request source (e.g., IP address).
        """
        if key not in self.request_records:
            return
        
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds
        
        self.request_records[key] = [
            timestamp for timestamp in self.request_records[key]
            if timestamp > cutoff_time
        ]
        
        # Remove empty entries
        if not self.request_records[key]:
            del self.request_records[key]


# PUBLIC_INTERFACE
def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.
    
    Args:
        length: Length of the token in bytes.
        
    Returns:
        Secure random token as a hexadecimal string.
    """
    import secrets
    return secrets.token_hex(length)


# PUBLIC_INTERFACE
def is_account_locked(failed_attempts: int) -> bool:
    """
    Check if an account should be locked based on failed attempts.
    
    Args:
        failed_attempts: Number of recent failed authentication attempts.
        
    Returns:
        True if the account should be locked, False otherwise.
    """
    return failed_attempts >= MAX_LOGIN_ATTEMPTS


# PUBLIC_INTERFACE
def get_lockout_time() -> datetime:
    """
    Get the time until which an account should be locked.
    
    Returns:
        Datetime representing when the lockout should expire.
    """
    return datetime.utcnow() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)


# Create default instances for common use
default_password_validator = PasswordValidator()
default_password_manager = PasswordManager(validator=default_password_validator)
default_rate_limiter = RateLimiter()