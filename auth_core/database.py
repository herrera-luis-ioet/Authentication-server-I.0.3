"""
Database configuration and session management for the Authentication Core Component.

This module provides SQLAlchemy setup for SQLite database, session management,
and database initialization functionality.
"""
import logging
import os
from contextlib import contextmanager
from typing import Any, Generator, Optional

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker, scoped_session

from auth_core.config import settings

# Create SQLAlchemy base class for models
Base = declarative_base()

# Configure SQLite to enforce foreign key constraints
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key constraints for SQLite."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


class Database:
    """Database connection and session management."""

    def __init__(self, db_url: str = None):
        """
        Initialize the database connection.

        Args:
            db_url: Database URL. If None, uses the URL from settings.
        """
        if db_url is None:
            db_url = settings.DATABASE_URL
        
        connect_args = {}
        if db_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        
        self.engine = create_engine(
            db_url, 
            connect_args=connect_args,
            echo=settings.DATABASE_ECHO
        )
        session_factory = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.SessionLocal = scoped_session(session_factory)

    def create_all(self) -> None:
        """Create all tables defined in the models."""
        Base.metadata.create_all(bind=self.engine)

    def drop_all(self) -> None:
        """Drop all tables. Use with caution, primarily for testing."""
        Base.metadata.drop_all(bind=self.engine)

    def get_session(self) -> Session:
        """
        Get a new database session.

        Returns:
            A new SQLAlchemy session.
        """
        return self.SessionLocal()

    @contextmanager
    def session_scope(self) -> Generator[Session, Any, None]:
        """
        Context manager for database sessions.

        Provides automatic commit/rollback and session closing.

        Yields:
            An active SQLAlchemy session.
        """
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()
            
    def refresh_object(self, session: Session, obj: Any) -> None:
        """
        Refresh an object from the database to prevent detached instance errors.
        
        This function handles detached objects by attempting to reattach them
        to the session before refreshing. If the object is not bound to a session,
        it will try to add it first.
        
        Args:
            session: Database session.
            obj: Object to refresh.
        """
        logger = logging.getLogger(__name__)
        
        if obj is not None and session is not None:
            try:
                # Check if object is attached to the session
                if hasattr(obj, '__mapper__') and not inspect(obj).persistent:
                    logger.debug(f"Object {obj} is detached, attempting to add to session")
                    try:
                        session.add(obj)
                        session.flush()
                    except Exception as e:
                        logger.warning(f"Failed to add detached object to session: {str(e)}")
                
                # Now try to refresh the object
                session.refresh(obj)
            except Exception as e:
                # If refresh fails, log the error with more details
                logger.warning(f"Failed to refresh object {type(obj).__name__}: {str(e)}")


# Default database instance
db = Database()


# PUBLIC_INTERFACE
def init_db(db_url: str = None) -> None:
    """
    Initialize the database with all required tables.

    Args:
        db_url: Optional database URL. If None, uses SQLite with the default path.
    """
    global db
    db = Database(db_url)
    db.create_all()


# PUBLIC_INTERFACE
def get_session() -> Session:
    """
    Get a new database session.

    Returns:
        A new SQLAlchemy session.
    """
    return db.get_session()


# PUBLIC_INTERFACE
@contextmanager
def session_scope() -> Generator[Session, Any, None]:
    """
    Context manager for database sessions.

    Provides automatic commit/rollback and session closing.

    Yields:
        An active SQLAlchemy session.
    """
    with db.session_scope() as session:
        yield session


# PUBLIC_INTERFACE
def refresh_object(session: Session, obj: Any) -> None:
    """
    Refresh an object from the database to prevent detached instance errors.
    
    This function handles detached objects by attempting to reattach them
    to the session before refreshing. If the object is not bound to a session,
    it will try to add it first.
    
    Args:
        session: Database session.
        obj: Object to refresh.
    """
    db.refresh_object(session, obj)
