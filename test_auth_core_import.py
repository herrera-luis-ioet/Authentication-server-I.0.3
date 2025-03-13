# Simple test script to check if the auth_core module can be imported
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Try to import the auth_core module
try:
    import auth_core
    print(f"SUCCESS: auth_core module imported successfully!")
except ImportError as e:
    print(f"FAILED: Import error: {e}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")