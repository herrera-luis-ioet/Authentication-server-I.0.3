"""
Test script to verify that the pydantic_settings module can be imported and the Settings class works correctly.
"""
import sys
print(f"Python version: {sys.version}")

try:
    print("Importing pydantic_settings...")
    import pydantic_settings
    print(f"pydantic_settings version: {pydantic_settings.__version__}")
    print("pydantic_settings imported successfully")
except ImportError as e:
    print(f"Error importing pydantic_settings: {e}")
    sys.exit(1)

try:
    print("\nImporting Settings from auth_core.config.settings...")
    from auth_core.config.settings import Settings, get_settings
    print("Settings class imported successfully")
    
    print("\nCreating Settings instance...")
    settings = get_settings()
    print("Settings instance created successfully")
    
    print("\nAccessing some settings values:")
    print(f"APP_NAME: {settings.APP_NAME}")
    print(f"JWT_ALGORITHM: {settings.JWT_ALGORITHM}")
    print(f"DATABASE_URL: {settings.DATABASE_URL}")
    
    print("\nAll tests passed successfully!")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)