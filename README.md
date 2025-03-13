# Authentication Core Component

A secure, high-performance authentication service built with Python and FastAPI that provides JWT token generation, user credential verification, token validation/refresh, and brute force attack prevention.

## Features

- **Secure JWT Token Generation**: Create and manage JSON Web Tokens with configurable expiration
- **User Credential Verification**: Securely verify user credentials with password hashing
- **Token Validation and Refresh**: Validate tokens and provide refresh capabilities
- **Brute Force Attack Prevention**: Rate limiting and account lockout mechanisms
- **Security Standards Compliance**: Follows OWASP security best practices
- **RESTful API**: Clean, well-documented API endpoints
- **Database Integration**: SQLite storage for user data and token management

## Tech Stack

- **Python 3.9+**
- **FastAPI**: High-performance web framework
- **PyJWT**: JWT token handling
- **Cryptography**: Secure cryptographic operations
- **SQLAlchemy**: ORM for database operations
- **SQLite**: Lightweight database
- **Poetry/pip**: Dependency management

## Installation

### Using Poetry (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/auth-core.git
cd auth-core

# Install dependencies with Poetry
poetry install

# Activate the virtual environment
poetry shell
```

### Using pip

```bash
# Clone the repository
git clone https://github.com/yourusername/auth-core.git
cd auth-core

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root with the following variables:

```
JWT_SECRET_KEY=your_secret_key_here
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
DATABASE_URL=sqlite:///./auth.db
```

## Usage

### Starting the Server

```bash
# Using Poetry
poetry run uvicorn auth_core.main:app --reload

# Using pip
uvicorn auth_core.main:app --reload
```

The API will be available at `http://localhost:8000`.

### API Documentation

Once the server is running, you can access the interactive API documentation at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Basic Usage Examples

#### User Registration

```python
import requests

response = requests.post(
    "http://localhost:8000/auth/register",
    json={
        "username": "user@example.com",
        "password": "securepassword123",
        "full_name": "John Doe"
    }
)
print(response.json())
```

#### User Authentication

```python
import requests

response = requests.post(
    "http://localhost:8000/auth/token",
    data={
        "username": "user@example.com",
        "password": "securepassword123"
    }
)
tokens = response.json()
access_token = tokens["access_token"]
refresh_token = tokens["refresh_token"]
```

#### Using the Access Token

```python
import requests

headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(
    "http://localhost:8000/users/me",
    headers=headers
)
print(response.json())
```

#### Refreshing the Token

```python
import requests

response = requests.post(
    "http://localhost:8000/auth/refresh",
    json={"refresh_token": refresh_token}
)
new_tokens = response.json()
```

## Development

### Running Tests

```bash
# Using Poetry
poetry run pytest

# Using pip
pytest
```

### Code Formatting and Linting

```bash
# Format code with Black
black auth_core

# Sort imports with isort
isort auth_core

# Lint with flake8
flake8 auth_core

# Type checking with mypy
mypy auth_core
```

## Project Structure

```
auth_core/
├── __init__.py
├── config/         # Configuration settings
├── models/         # Database models
├── services/       # Business logic
├── utils/          # Utility functions
└── tests/          # Test suite
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.