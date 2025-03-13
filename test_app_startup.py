"""
Test script to verify that the application can start up properly.
"""
import sys
import importlib
import traceback

def test_import(module_name):
    """Test importing a module and print the result."""
    print(f"Testing import of {module_name}...")
    try:
        module = importlib.import_module(module_name)
        print(f"✓ Successfully imported {module_name}")
        return module
    except Exception as e:
        print(f"✗ Failed to import {module_name}: {e}")
        traceback.print_exc()
        return None

def test_settings():
    """Test the settings module."""
    print("\n=== Testing settings module ===")
    try:
        from auth_core.config.settings import settings
        print("✓ Settings loaded successfully")
        print(f"  - APP_NAME: {settings.APP_NAME}")
        print(f"  - DATABASE_URL: {settings.DATABASE_URL}")
        print(f"  - JWT_ALGORITHM: {settings.JWT_ALGORITHM}")
        return True
    except Exception as e:
        print(f"✗ Failed to load settings: {e}")
        traceback.print_exc()
        return False

def test_app_creation():
    """Test creating the FastAPI application."""
    print("\n=== Testing FastAPI app creation ===")
    try:
        import main
        print("✓ FastAPI app created successfully")
        print(f"  - App title: {main.app.title}")
        print(f"  - App version: {main.app.version}")
        return True
    except Exception as e:
        print(f"✗ Failed to create FastAPI app: {e}")
        traceback.print_exc()
        return False

def test_database_init():
    """Test database initialization."""
    print("\n=== Testing database initialization ===")
    try:
        from auth_core.database import init_db, get_session
        from auth_core.config.settings import settings
        
        init_db(settings.DATABASE_URL)
        # Try to get a session to verify the database connection
        session = get_session()
        session.close()
        print("✓ Database initialized successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to initialize database: {e}")
        traceback.print_exc()
        return False

def run_all_tests():
    """Run all tests and return True if all passed."""
    print("Starting application startup tests...\n")
    
    # Test importing key modules
    modules_to_test = [
        "fastapi",
        "pydantic",
        "pydantic_settings",
        "auth_core",
        "auth_core.config",
        "auth_core.api",
        "auth_core.token",
        "auth_core.auth",
        "auth_core.database"
    ]
    
    all_imports_successful = True
    for module in modules_to_test:
        if test_import(module) is None:
            all_imports_successful = False
    
    # Test specific components
    settings_ok = test_settings()
    database_ok = test_database_init()
    app_ok = test_app_creation()
    
    # Print summary
    print("\n=== Test Summary ===")
    print(f"Module imports: {'✓ PASS' if all_imports_successful else '✗ FAIL'}")
    print(f"Settings: {'✓ PASS' if settings_ok else '✗ FAIL'}")
    print(f"Database: {'✓ PASS' if database_ok else '✗ FAIL'}")
    print(f"FastAPI app: {'✓ PASS' if app_ok else '✗ FAIL'}")
    
    all_passed = all_imports_successful and settings_ok and database_ok and app_ok
    print(f"\nOverall result: {'✓ ALL TESTS PASSED' if all_passed else '✗ SOME TESTS FAILED'}")
    
    return all_passed

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
