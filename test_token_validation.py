
import os
import pytest
from auth_core.token import is_token_valid
from auth_core.config.jwt_config import get_jwt_settings, TOKEN_TYPE_ACCESS
import jwt
from datetime import datetime, timedelta

def test_token_validation(test_user, db_session):
    # Create a token
    jwt_settings = get_jwt_settings()
    token_id = 'test-token-validation'
    expiry_time = datetime.utcnow() + timedelta(hours=1)
    payload = {
        'sub': str(test_user.id),
        'jti': token_id,
        'type': TOKEN_TYPE_ACCESS,
        'iat': datetime.utcnow(),
        'exp': expiry_time,
        'username': test_user.username,
        'email': test_user.email,
        'role': test_user.role.value
    }
    
    token = jwt.encode(
        payload,
        jwt_settings['secret_key'],
        algorithm=jwt_settings['algorithm']
    )
    
    # Validate the token
    assert is_token_valid(token), 'Token should be valid'
