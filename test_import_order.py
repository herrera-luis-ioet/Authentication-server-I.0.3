# Simple test script to check if the import order is correct
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Try to import the modules in the correct order
try:
    # First import config
    from auth_core.config import TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH
    print("SUCCESS: Config imported successfully!")
    
    # Then import database
    from auth_core.database import Base, init_db, get_session, session_scope
    print("SUCCESS: Database imported successfully!")
    
    # Then import models
    from auth_core.models import User, UserRole, Token, TokenType, TokenStatus, AuthAttempt, AuthAttemptResult
    print("SUCCESS: Models imported successfully!")
    
    # Finally import token
    from auth_core.token import TokenError, create_access_token
    print("SUCCESS: Token imported successfully!")
    
    print("All imports successful! The import order is correct.")
except ImportError as e:
    print(f"FAILED: Import error: {e}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")