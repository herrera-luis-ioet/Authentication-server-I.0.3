# Simple test script to check if the circular import issue is resolved
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Try to import the modules directly
try:
    from auth_core.auth import AuthError
    from auth_core.token import TokenError
    print("SUCCESS: Both modules imported successfully!")
except ImportError as e:
    print(f"FAILED: Import error: {e}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")