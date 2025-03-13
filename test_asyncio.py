# Simple test script to check if the asyncio error is resolved
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

# Try to import asyncio and check if iscoroutine is available
try:
    import asyncio
    print(f"asyncio imported successfully!")
    
    if hasattr(asyncio, 'iscoroutine'):
        print(f"SUCCESS: asyncio.iscoroutine is available!")
    else:
        print(f"ERROR: asyncio.iscoroutine is not available!")
except ImportError as e:
    print(f"FAILED: Import error: {e}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")