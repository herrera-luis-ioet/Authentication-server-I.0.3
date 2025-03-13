"""
Authentication functionality for the Authentication Core Component.

This module provides user authentication, registration, and account management
functionality, including brute force attack prevention and account lockout.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth_core.database import session_scope
from auth_core.models import (AuthAttempt, AuthAttemptResult, Token, TokenType,
                             User, UserRole)
from auth_core.security import (MAX_LOGIN_ATTEMPTS, default_password_manager,
                              get_lockout_time, is_account_locked)
from auth_core.token import (TokenError, create_token_pair, revoke_all_user_tokens,
                           validate_token)

# Configure logging
logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Base exception for authentication-related errors."""
    pass


class UserNotFoundError(AuthError):
    """Exception raised when a user is not found."""
    pass


class InvalidCredentialsError(AuthError):
    """Exception raised when credentials are invalid."""
    pass


class AccountLockedError(AuthError):
    """Exception raised when an account is locked due to too many failed attempts."""
    pass


class UserExistsError(AuthError):
    """Exception raised when trying to create a user that already exists."""
    pass


class AuthenticationManager:
    """
    Authentication manager for user authentication and registration.
    
    Provides functionality for user authentication, registration, and account management.
    """
    
    def __init__(self, session: Optional[Session] = None):
        """
        Initialize the authentication manager.
        
        Args:
            session: Optional database session. If not provided, a new session
                    will be created for each operation.
        """
        self.session = session
    
    # PUBLIC_INTERFACE
    def authenticate_user(
        self,
        username_or_email: str,
        password: str,
        ip_address: str,
        user_agent: Optional[str] = None
    ) -> Tuple[User, Dict[str, str]]:
        """
        Authenticate a user and generate tokens.
        
        Args:
            username_or_email: Username or email of the user.
            password: User's password.
            ip_address: IP address of the client.
            user_agent: Optional user agent string.
            
        Returns:
            Tuple containing:
                - Authenticated user object.
                - Dictionary with access and refresh tokens.
                
        Raises:
            UserNotFoundError: If the user is not found.
            InvalidCredentialsError: If the credentials are invalid.
            AccountLockedError: If the account is locked due to too many failed attempts.
        """
        # Use provided session or create a new one
        with self._get_session_context() as session:
            # Check if the IP is locked out due to too many failed attempts
            self._check_ip_lockout(session, ip_address)
            
            # Try to find the user
            user = self._find_user(session, username_or_email)
            if not user:
                # Record failed attempt with username
                self._record_auth_attempt(
                    session, 
                    None, 
                    ip_address, 
                    user_agent, 
                    username_or_email, 
                    AuthAttemptResult.FAILURE
                )
                raise UserNotFoundError(f"User not found: {username_or_email}")
            
            # Check if the user account is locked
            self._check_user_lockout(session, user, ip_address)
            
            # Verify password
            if not user.verify_password(password):
                # Record failed attempt
                self._record_auth_attempt(
                    session, 
                    user.id, 
                    ip_address, 
                    user_agent, 
                    None, 
                    AuthAttemptResult.FAILURE
                )
                raise InvalidCredentialsError("Invalid password")
            
            # Record successful attempt
            self._record_auth_attempt(
                session, 
                user.id, 
                ip_address, 
                user_agent, 
                None, 
                AuthAttemptResult.SUCCESS
            )
            
            # Generate tokens
            tokens = create_token_pair(user, session)
            
            return user, tokens
    
    # PUBLIC_INTERFACE
    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.USER,
        auto_login: bool = False,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[User, Optional[Dict[str, str]]]:
        """
        Register a new user.
        
        Args:
            username: Username for the new user.
            email: Email address for the new user.
            password: Password for the new user.
            role: Role for the new user (default: USER).
            auto_login: Whether to automatically log in the user after registration.
            ip_address: IP address of the client (required if auto_login is True).
            user_agent: Optional user agent string.
            
        Returns:
            Tuple containing:
                - Newly created user object.
                - Dictionary with access and refresh tokens (if auto_login is True).
                
        Raises:
            UserExistsError: If a user with the same username or email already exists.
            ValueError: If auto_login is True but ip_address is not provided.
        """
        if auto_login and not ip_address:
            raise ValueError("IP address is required for auto-login")
        
        # Use provided session or create a new one
        with self._get_session_context() as session:
            # Check if user already exists
            existing_user = session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                if existing_user.username == username:
                    raise UserExistsError(f"Username already exists: {username}")
                else:
                    raise UserExistsError(f"Email already exists: {email}")
            
            # Create new user
            user = User(
                username=username,
                email=email,
                role=role,
                is_active=True
            )
            
            # Hash and set password
            user.set_password(password)
            
            try:
                session.add(user)
                session.commit()
                logger.info(f"User registered: {username}")
                
                # Auto-login if requested
                if auto_login:
                    # Record successful authentication
                    self._record_auth_attempt(
                        session, 
                        user.id, 
                        ip_address, 
                        user_agent, 
                        None, 
                        AuthAttemptResult.SUCCESS
                    )
                    
                    # Generate tokens
                    tokens = create_token_pair(user, session)
                    return user, tokens
                
                return user, None
                
            except IntegrityError as e:
                session.rollback()
                logger.error(f"Failed to register user: {str(e)}")
                raise UserExistsError("Failed to register user due to constraint violation")
    
    # PUBLIC_INTERFACE
    def logout_user(self, token: str) -> bool:
        """
        Log out a user by revoking their token.
        
        Args:
            token: JWT token to revoke.
            
        Returns:
            True if the token was successfully revoked, False otherwise.
        """
        try:
            # Validate and decode the token
            payload = validate_token(token)
            
            # Get user ID from token
            user_id = int(payload.get("sub"))
            token_id = payload.get("jti")
            
            # Revoke the token
            with self._get_session_context() as session:
                # Find the token in the database
                db_token = session.query(Token).filter(Token.token_id == token_id).first()
                
                if db_token:
                    db_token.revoke()
                    session.commit()
                    logger.info(f"Token revoked for user ID: {user_id}")
                    return True
                
                return False
                
        except TokenError as e:
            logger.warning(f"Failed to revoke token: {str(e)}")
            return False
    
    # PUBLIC_INTERFACE
    def logout_user_all_devices(self, user_id: int, current_token_id: Optional[str] = None) -> int:
        """
        Log out a user from all devices by revoking all their tokens.
        
        Args:
            user_id: ID of the user to log out.
            current_token_id: Optional ID of the current token to exclude from revocation.
            
        Returns:
            Number of tokens revoked.
        """
        return revoke_all_user_tokens(user_id, current_token_id)
    
    # PUBLIC_INTERFACE
    def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change a user's password.
        
        Args:
            user_id: ID of the user.
            current_password: Current password for verification.
            new_password: New password to set.
            
        Returns:
            True if the password was successfully changed, False otherwise.
            
        Raises:
            UserNotFoundError: If the user is not found.
            InvalidCredentialsError: If the current password is invalid.
        """
        with self._get_session_context() as session:
            # Find the user
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise UserNotFoundError(f"User not found with ID: {user_id}")
            
            # Verify current password
            if not user.verify_password(current_password):
                raise InvalidCredentialsError("Current password is incorrect")
            
            # Set new password
            user.set_password(new_password)
            session.commit()
            
            # Revoke all tokens except the current one
            # This forces re-login on all other devices
            logger.info(f"Password changed for user ID: {user_id}")
            
            return True
    
    # PUBLIC_INTERFACE
    def deactivate_user(self, user_id: int) -> bool:
        """
        Deactivate a user account.
        
        Args:
            user_id: ID of the user to deactivate.
            
        Returns:
            True if the user was successfully deactivated, False otherwise.
            
        Raises:
            UserNotFoundError: If the user is not found.
        """
        with self._get_session_context() as session:
            # Find the user
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise UserNotFoundError(f"User not found with ID: {user_id}")
            
            # Deactivate the user
            user.is_active = False
            session.commit()
            
            # Revoke all tokens
            revoke_all_user_tokens(user_id)
            
            logger.info(f"User deactivated: {user_id}")
            return True
    
    # PUBLIC_INTERFACE
    def reactivate_user(self, user_id: int) -> bool:
        """
        Reactivate a deactivated user account.
        
        Args:
            user_id: ID of the user to reactivate.
            
        Returns:
            True if the user was successfully reactivated, False otherwise.
            
        Raises:
            UserNotFoundError: If the user is not found.
        """
        with self._get_session_context() as session:
            # Find the user
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise UserNotFoundError(f"User not found with ID: {user_id}")
            
            # Reactivate the user
            user.is_active = True
            session.commit()
            
            logger.info(f"User reactivated: {user_id}")
            return True
    
    def _get_session_context(self):
        """
        Get a session context manager.
        
        Returns:
            Session context manager.
        """
        if self.session:
            # If a session was provided, use it without creating a new one
            class SessionContext:
                def __init__(self, session):
                    self.session = session
                
                def __enter__(self):
                    return self.session
                
                def __exit__(self, exc_type, exc_val, exc_tb):
                    # Don't close the session, as it was provided externally
                    pass
            
            return SessionContext(self.session)
        else:
            # Otherwise, use the session_scope context manager
            return session_scope()
    
    def _find_user(self, session: Session, username_or_email: str) -> Optional[User]:
        """
        Find a user by username or email.
        
        Args:
            session: Database session.
            username_or_email: Username or email to search for.
            
        Returns:
            User object if found, None otherwise.
        """
        return session.query(User).filter(
            ((User.username == username_or_email) | (User.email == username_or_email)) &
            (User.is_active == True)
        ).first()
    
    def _check_ip_lockout(self, session: Session, ip_address: str) -> None:
        """
        Check if an IP address is locked out due to too many failed attempts.
        
        Args:
            session: Database session.
            ip_address: IP address to check.
            
        Raises:
            AccountLockedError: If the IP address is locked out.
        """
        # Get recent failed attempts from this IP
        recent_failures = AuthAttempt.get_recent_failures(
            session, ip_address, minutes=LOGIN_LOCKOUT_MINUTES
        )
        
        # Check if the IP is locked out
        if len(recent_failures) >= MAX_LOGIN_ATTEMPTS:
            logger.warning(f"IP address locked out due to too many failed attempts: {ip_address}")
            raise AccountLockedError(
                f"Too many failed login attempts. Try again after {LOGIN_LOCKOUT_MINUTES} minutes."
            )
    
    def _check_user_lockout(self, session: Session, user: User, ip_address: str) -> None:
        """
        Check if a user account is locked due to too many failed attempts.
        
        Args:
            session: Database session.
            user: User object to check.
            ip_address: Current IP address.
            
        Raises:
            AccountLockedError: If the user account is locked out.
        """
        # Get recent failed attempts for this user
        recent_failures = AuthAttempt.get_recent_failures(
            session, ip_address, minutes=LOGIN_LOCKOUT_MINUTES, username=user.username
        )
        
        # Check if the account is locked
        if is_account_locked(len(recent_failures)):
            logger.warning(f"User account locked due to too many failed attempts: {user.username}")
            lockout_time = get_lockout_time()
            raise AccountLockedError(
                f"Account locked due to too many failed login attempts. "
                f"Try again after {lockout_time.strftime('%H:%M:%S')}."
            )
    
    def _record_auth_attempt(
        self,
        session: Session,
        user_id: Optional[int],
        ip_address: str,
        user_agent: Optional[str],
        username_attempt: Optional[str],
        result: AuthAttemptResult
    ) -> AuthAttempt:
        """
        Record an authentication attempt.
        
        Args:
            session: Database session.
            user_id: ID of the user, or None if user not found.
            ip_address: IP address of the client.
            user_agent: User agent string, or None if not available.
            username_attempt: Username that was attempted, or None if not applicable.
            result: Result of the authentication attempt.
            
        Returns:
            Created AuthAttempt object.
        """
        auth_attempt = AuthAttempt(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            username_attempt=username_attempt,
            result=result
        )
        
        session.add(auth_attempt)
        session.commit()
        
        return auth_attempt


# Create a default authentication manager for common use
default_auth_manager = AuthenticationManager()


# PUBLIC_INTERFACE
def authenticate_user(
    username_or_email: str,
    password: str,
    ip_address: str,
    user_agent: Optional[str] = None
) -> Tuple[User, Dict[str, str]]:
    """
    Authenticate a user and generate tokens.
    
    Args:
        username_or_email: Username or email of the user.
        password: User's password.
        ip_address: IP address of the client.
        user_agent: Optional user agent string.
        
    Returns:
        Tuple containing:
            - Authenticated user object.
            - Dictionary with access and refresh tokens.
    """
    return default_auth_manager.authenticate_user(
        username_or_email, password, ip_address, user_agent
    )


# PUBLIC_INTERFACE
def register_user(
    username: str,
    email: str,
    password: str,
    role: UserRole = UserRole.USER,
    auto_login: bool = False,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Tuple[User, Optional[Dict[str, str]]]:
    """
    Register a new user.
    
    Args:
        username: Username for the new user.
        email: Email address for the new user.
        password: Password for the new user.
        role: Role for the new user (default: USER).
        auto_login: Whether to automatically log in the user after registration.
        ip_address: IP address of the client (required if auto_login is True).
        user_agent: Optional user agent string.
        
    Returns:
        Tuple containing:
            - Newly created user object.
            - Dictionary with access and refresh tokens (if auto_login is True).
    """
    return default_auth_manager.register_user(
        username, email, password, role, auto_login, ip_address, user_agent
    )


# PUBLIC_INTERFACE
def logout_user(token: str) -> bool:
    """
    Log out a user by revoking their token.
    
    Args:
        token: JWT token to revoke.
        
    Returns:
        True if the token was successfully revoked, False otherwise.
    """
    return default_auth_manager.logout_user(token)


# PUBLIC_INTERFACE
def logout_user_all_devices(user_id: int, current_token_id: Optional[str] = None) -> int:
    """
    Log out a user from all devices by revoking all their tokens.
    
    Args:
        user_id: ID of the user to log out.
        current_token_id: Optional ID of the current token to exclude from revocation.
        
    Returns:
        Number of tokens revoked.
    """
    return default_auth_manager.logout_user_all_devices(user_id, current_token_id)


# PUBLIC_INTERFACE
def change_password(user_id: int, current_password: str, new_password: str) -> bool:
    """
    Change a user's password.
    
    Args:
        user_id: ID of the user.
        current_password: Current password for verification.
        new_password: New password to set.
        
    Returns:
        True if the password was successfully changed, False otherwise.
    """
    return default_auth_manager.change_password(user_id, current_password, new_password)


# PUBLIC_INTERFACE
def get_failed_login_attempts(
    session: Session,
    ip_address: str,
    minutes: int = 30,
    username: Optional[str] = None
) -> List[AuthAttempt]:
    """
    Get recent failed login attempts.
    
    Args:
        session: Database session.
        ip_address: IP address to check.
        minutes: Time window in minutes.
        username: Optional username to filter attempts.
        
    Returns:
        List of failed authentication attempts.
    """
    return AuthAttempt.get_recent_failures(session, ip_address, minutes, username)