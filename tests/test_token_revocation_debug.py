
import os
import pytest
import logging
from auth_core.token import is_token_valid, get_token_data
from auth_core.models import Token, TokenStatus

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_token_for_revocation_debug(token_for_revocation, db_session):
    # Get token ID
    token_id = get_token_data(token_for_revocation)['jti']
    
    # Check token in database
    db_token = db_session.query(Token).filter_by(token_id=token_id).first()
    logger.info(f'Token ID: {token_id}')
    logger.info(f'Token status in database: {db_token.status if db_token else None}')
    logger.info(f'Token user_id: {db_token.user_id if db_token else None}')
    logger.info(f'Token expires_at: {db_token.expires_at if db_token else None}')
    
    # Check if token is valid
    valid = is_token_valid(token_for_revocation)
    logger.info(f'is_token_valid result: {valid}')
    
    # This assertion should pass if the token is valid
    assert valid, 'Token should be valid before revocation'
