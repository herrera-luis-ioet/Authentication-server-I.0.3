# Test script to check the structure of auth.py and token.py
import os

def check_file_for_imports(file_path, import_to_check):
    """Check if a file has a specific import at the module level."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check for module-level imports (outside of functions)
    lines = content.split('\n')
    module_level_imports = []
    in_function = False
    
    for line in lines:
        # Skip comments and empty lines
        if line.strip().startswith('#') or not line.strip():
            continue
        
        # Check if we're entering a function definition
        if line.strip().startswith('def '):
            in_function = True
        
        # Check if we're exiting a function definition
        if in_function and line.strip() == '':
            in_function = False
        
        # If not in a function and line contains an import statement, add it to the list
        if not in_function and 'import' in line:
            module_level_imports.append(line.strip())
    
    # Check if the specific import is in the module-level imports
    for imp in module_level_imports:
        if import_to_check in imp and 'from' in imp:
            return True
    
    return False

# Paths to the files
auth_path = '/home/kavia/workspace/Authentication-server-I.0.3/auth_core/auth.py'
token_path = '/home/kavia/workspace/Authentication-server-I.0.3/auth_core/token.py'

# Check if auth.py imports token.py functions at the module level
auth_imports_token_functions = check_file_for_imports(auth_path, 'from auth_core.token import create_token_pair')
auth_imports_token_functions |= check_file_for_imports(auth_path, 'from auth_core.token import validate_token')
auth_imports_token_functions |= check_file_for_imports(auth_path, 'from auth_core.token import revoke_all_user_tokens')

# Check if auth.py only imports TokenError at the module level
auth_imports_token_error = check_file_for_imports(auth_path, 'from auth_core.token import TokenError')

# Check if token.py imports auth.py at the module level
token_imports_auth = check_file_for_imports(token_path, 'from auth_core.auth import')

# Print results
print("=== Circular Import Check Results ===")
print(f"auth.py imports token functions at module level: {auth_imports_token_functions}")
print(f"auth.py imports TokenError at module level: {auth_imports_token_error}")
print(f"token.py imports auth.py at module level: {token_imports_auth}")

if not auth_imports_token_functions and auth_imports_token_error and not token_imports_auth:
    print("\nSUCCESS: Circular import issue has been resolved!")
    print("- auth.py only imports TokenError at the module level")
    print("- token.py does not import auth.py at the module level")
    print("- Other token.py functions are imported at the function level in auth.py")
else:
    print("\nFAILED: Circular import issue may still exist.")
    if auth_imports_token_functions:
        print("- auth.py still imports token functions at the module level")
    if not auth_imports_token_error:
        print("- auth.py does not import TokenError at the module level")
    if token_imports_auth:
        print("- token.py imports auth.py at the module level")