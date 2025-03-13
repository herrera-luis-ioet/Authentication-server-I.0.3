# Simple test script to check if we can import api.py without circular import issues
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Try to import the api module
try:
    from auth_core.api import router
    print("SUCCESS: API module imported successfully!")
except ImportError as e:
    print(f"FAILED: Import error: {e}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")