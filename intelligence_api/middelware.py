"""
AuthGuard Enterprise - Middleware
Security middleware for API request validation and error handling
"""

import os
import logging
from functools import wraps
from typing import Callable, Any
from flask import request, jsonify
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_db import get_cache, MerchantDB

logger = logging.getLogger(__name__)


def require_api_key(f: Callable) -> Callable:
    """
    Middleware to validate API key and check merchant credits
    
    Checks:
    1. API key presence in headers
    2. API key validity
    3. Merchant account status
    4. Available credits
    
    Attaches merchant_id to request object if valid
    """
    @wraps(f)
    def decorated_function(*args, **kwargs) -> Any:
        # Get API key from header
        api_key = request.headers.get('X-API-KEY')
        
        if not api_key:
            logger.warning(f"Missing API key from {request.remote_addr}")
            return jsonify({
                'error': 'Missing API Key',
                'message': 'X-API-KEY header is required'
            }), 401
        
        # Check cache first for performance
        cache = get_cache()
        cache_key = f"api_key:{api_key}"
        
        merchant_data = cache.get(cache_key)
        
        if not merchant_data:
            # Not in cache, query database
            merchant_data = MerchantDB.get_merchant_by_api_key(api_key)
            
            if not merchant_data:
                logger.warning(f"Invalid API key attempt from {request.remote_addr}")
                return jsonify({
                    'error': 'Invalid API Key',
                    'message': 'The provided API key is not valid'
                }), 403
            
            # Cache for 5 minutes
            cache.set(cache_key, merchant_data, ttl=300)
        
        # Check merchant status
        if merchant_data.get('status') != 'active':
            logger.warning(f"Inactive merchant attempt: {merchant_data.get('id')}")
            return jsonify({
                'error': 'Account Suspended',
                'message': 'Your account has been suspended. Please contact support.'
            }), 403
        
        # Check credits
        credits = merchant_data.get('credits', 0)
        if credits <= 0:
            logger.warning(f"Zero credits: {merchant_data.get('id')}")
            return jsonify({
                'error': 'Payment Required',
                'message': 'Your account has run out of credits. Please add more credits to continue.',
                'credits_remaining': 0
            }), 402
        
        # Attach merchant ID to request object
        request.merchant_id = merchant_data.get('id')
        request.merchant_data = merchant_data
        
        # Log API call (optional, can be disabled for performance)
        if os.getenv('LOG_API_CALLS', 'false').lower() == 'true':
            logger.info(
                f"API call: {request.method} {request.path} "
                f"from merchant={merchant_data.get('id')} "
                f"ip={request.remote_addr}"
            )
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_admin(f: Callable) -> Callable:
    """
    Middleware to require admin authentication
    (For internal endpoints)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs) -> Any:
        # Check for admin token
        admin_token = request.headers.get('X-Admin-Token')
        expected_token = os.getenv('ADMIN_TOKEN')
        
        if not admin_token or admin_token != expected_token:
            logger.warning(f"Unauthorized admin access attempt from {request.remote_addr}")
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Admin authentication required'
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


def handle_errors(f: Callable) -> Callable:
    """
    Global error handler for endpoints
    Catches and logs all exceptions
    """
    @wraps(f)
    def decorated_function(*args, **kwargs) -> Any:
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Validation error: {e}")
            return jsonify({
                'error': 'Validation Error',
                'message': str(e)
            }), 400
        except KeyError as e:
            logger.error(f"Missing field: {e}")
            return jsonify({
                'error': 'Missing Field',
                'message': f'Required field missing: {e}'
            }), 400
        except Exception as e:
            logger.error(f"Unhandled error: {e}", exc_info=True)
            return jsonify({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred'
            }), 500
    
    return decorated_function


def validate_json_schema(required_fields: list):
    """
    Middleware to validate JSON request body
    
    Usage:
        @validate_json_schema(['user_uid', 'telemetry'])
        def my_endpoint():
            ...
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs) -> Any:
            if not request.is_json:
                return jsonify({
                    'error': 'Invalid Content-Type',
                    'message': 'Request must be application/json'
                }), 400
            
            data = request.get_json()
            
            # Check required fields
            missing = [field for field in required_fields if field not in data]
            
            if missing:
                return jsonify({
                    'error': 'Missing Required Fields',
                    'fields': missing
                }), 400
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def log_request(f: Callable) -> Callable:
    """
    Middleware to log all requests (debugging)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs) -> Any:
        logger.debug(
            f"Request: {request.method} {request.path} "
            f"from {request.remote_addr} "
            f"ua={request.user_agent}"
        )
        return f(*args, **kwargs)
    
    return decorated_function


def cors_preflight(f: Callable) -> Callable:
    """
    Handle OPTIONS preflight requests
    """
    @wraps(f)
    def decorated_function(*args, **kwargs) -> Any:
        if request.method == 'OPTIONS':
            response = jsonify({'status': 'ok'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,X-API-KEY')
            response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
            return response, 200
        return f(*args, **kwargs)
    
    return decorated_function