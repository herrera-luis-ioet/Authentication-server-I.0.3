
import os
import pytest
from auth_core.token import is_token_valid
from auth_core.config.jwt_config import get_jwt_settings, TOKEN_TYPE_ACCESS
import jwt
from datetime import datetime, timedelta
from auth_core.models import Token, TokenStatus, TokenType

def test_token_validation_debug(test_user, db_session):
    # Create a token
    jwt_settings = get_jwt_settings()
    token_id = 'test-token-validation-debug'
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
    
    # Delete any existing token with the same ID
    db_session.query(Token).filter_by(token_id=token_id).delete()
    db_session.commit()
    
    # Create token in database
    db_token = Token(
        token_id=token_id,
        user_id=test_user.id,
        token_type=TokenType.ACCESS,
        status=TokenStatus.ACTIVE,
        expires_at=expiry_time
    )
    
    db_session.add(db_token)
    db_session.commit()
    db_session.refresh(db_token)
    
    # Validate the token
    assert is_token_valid(token), 'Token should be valid'
