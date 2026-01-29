"""
AuthGuard Enterprise - Intelligence API
High-performance behavioral analysis API with Redis caching
"""

import os
import sys
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import json

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared_db import (
    get_db, get_cache, MerchantDB, ProfileDB, LogDB, 
    Collections, health_check
)
from intelligence_api.core_logic import analyze_risk, detect_bot_movement
from intelligence_api.middleware import require_api_key, handle_errors
from intelligence_api.otp_service import OTPService
from intelligence_api.geo_service import GeoLocationService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['JSON_SORT_KEYS'] = False

# Enable CORS
CORS(app, resources={
    r"/v1/*": {
        "origins": os.getenv('CORS_ORIGINS', '*').split(','),
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-API-KEY", "Authorization"]
    }
})

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour", "100 per minute"],
    storage_uri=f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}"
)

# Initialize services
otp_service = OTPService()
geo_service = GeoLocationService()

# ========================================
# HEALTH CHECK
# ========================================

@app.route('/health', methods=['GET'])
def health():
    """API health check endpoint"""
    status = health_check()
    
    if status['firestore'] and status['redis']:
        return jsonify({
            'status': 'healthy',
            'timestamp': status['timestamp'],
            'services': status
        }), 200
    else:
        return jsonify({
            'status': 'degraded',
            'timestamp': status['timestamp'],
            'services': status
        }), 503


@app.route('/v1/status', methods=['GET'])
@limiter.limit("10 per minute")
def api_status():
    """Detailed API status"""
    return jsonify({
        'api_version': '2.0.0',
        'status': 'operational',
        'timestamp': datetime.utcnow().isoformat(),
        'endpoints': {
            'verify': '/v1/verify',
            'profile': '/v1/profile',
            'recover': '/v1/recover/*'
        }
    }), 200


# ========================================
# MAIN VERIFICATION ENDPOINT
# ========================================

@app.route('/v1/verify', methods=['POST', 'OPTIONS'])
@limiter.limit("500 per hour")
@require_api_key
@handle_errors
def verify_session():
    """
    Main behavioral verification endpoint
    
    This is called continuously by the client SDK (every 4 seconds)
    to analyze behavioral patterns in real-time.
    
    Request Body:
        {
            "user_uid": "user_12345",
            "telemetry": {
                "flight_vec": [120, 135, 110, ...],
                "dwell_vec": [45, 50, 48, ...],
                "mouse_path": [{x, y, t}, ...],
                "bot_flags": ["AUTOMATION_TOOL_DETECTED"],
                "fingerprint": {
                    "userAgent": "...",
                    "screenRes": "1920x1080",
                    "cores": 8,
                    "timezone": "America/New_York"
                }
            },
            "geo_location": {
                "lat": 40.7128,
                "lon": -74.0060
            }
        }
    
    Response:
        {
            "decision": "ALLOW" | "VERIFY" | "LOCK",
            "risk_score": 0-100,
            "reasons": ["..."],
            "metrics": {...},
            "session_id": "..."
        }
    """
    try:
        # Get merchant ID from middleware
        merchant_id = request.merchant_id
        
        # Parse request
        data = request.get_json()
        user_uid = data.get('user_uid')
        telemetry = data.get('telemetry', {})
        geo_location = data.get('geo_location')
        
        if not user_uid:
            return jsonify({
                'error': 'Missing user_uid'
            }), 400
        
        # Get or create user profile
        profile = ProfileDB.get_profile(merchant_id, user_uid)
        
        if not profile:
            # First time user - create baseline profile
            profile = {
                'merchant_id': merchant_id,
                'user_uid': user_uid,
                'baseline_stats': {},
                'trust_score': 100,
                'is_locked': False,
                'total_verifications': 0,
                'known_fingerprints': []
            }
            
            profile_id = ProfileDB.create_profile(
                merchant_id, 
                user_uid, 
                profile
            )
            profile['id'] = profile_id
            
            logger.info(f"New profile created: {user_uid}")
        
        # Update verification count
        profile['total_verifications'] = profile.get('total_verifications', 0) + 1
        
        # Enrich telemetry with geo data
        if geo_location:
            telemetry['geo_location'] = geo_location
        elif request.remote_addr:
            # Fallback: Get location from IP
            geo_data = geo_service.get_location_from_ip(request.remote_addr)
            if geo_data:
                telemetry['geo_location'] = geo_data
        
        # === CORE RISK ANALYSIS ===
        risk_score, reason, metrics = analyze_risk(telemetry, profile)
        
        # Determine decision
        if risk_score < int(os.getenv('RISK_THRESHOLD_LOW', 40)):
            decision = "ALLOW"
        elif risk_score < int(os.getenv('RISK_THRESHOLD_HIGH', 80)):
            decision = "VERIFY"
        else:
            decision = "LOCK"
            
            # Lock the profile
            ProfileDB.lock_profile(profile['id'], reason)
        
        # Update profile with new data
        if decision != "LOCK":
            # Update baseline statistics
            update_data = {
                'last_session_timestamp': datetime.utcnow(),
                'trust_score': max(0, 100 - risk_score)
            }
            
            # Add current fingerprint to known devices
            if 'fingerprint' in telemetry:
                known_fps = profile.get('known_fingerprints', [])
                current_fp = telemetry['fingerprint']
                
                # Only store unique fingerprints (max 5)
                if current_fp not in known_fps:
                    known_fps.append(current_fp)
                    known_fps = known_fps[-5:]  # Keep last 5
                    update_data['known_fingerprints'] = known_fps
            
            # Update geo location
            if 'geo_location' in telemetry:
                update_data['last_geo_location'] = telemetry['geo_location']
            
            # Update baseline stats (running average)
            if telemetry.get('flight_vec'):
                import numpy as np
                current_flight_mean = np.mean(telemetry['flight_vec'])
                
                old_stats = profile.get('baseline_stats', {})
                old_flight_mean = old_stats.get('flight_mean', current_flight_mean)
                
                # Exponential moving average (alpha = 0.3)
                new_flight_mean = 0.7 * old_flight_mean + 0.3 * current_flight_mean
                
                update_data['baseline_stats'] = {
                    'flight_mean': new_flight_mean,
                    'flight_std': np.std(telemetry['flight_vec'])
                }
            
            ProfileDB.update_profile(profile['id'], update_data)
        
        # Deduct API credits
        MerchantDB.deduct_credits(merchant_id, amount=1)
        
        # Log the verification
        log_data = {
            'user_uid': user_uid,
            'risk_score': risk_score,
            'decision': decision,
            'reason': reason,
            'event_type': 'behavioral_verification',
            'ip_address': request.remote_addr,
            'metrics': metrics
        }
        LogDB.create_log(merchant_id, log_data)
        
        # Build response
        response = {
            'decision': decision,
            'risk_score': risk_score,
            'reasons': metrics.get('risk_factors', []),
            'trust_score': 100 - risk_score,
            'session_id': f"sess_{datetime.utcnow().timestamp()}",
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add detailed metrics for VERIFY/LOCK decisions
        if decision in ['VERIFY', 'LOCK']:
            response['metrics'] = metrics
        
        logger.info(
            f"Verification: user={user_uid}, "
            f"risk={risk_score}, decision={decision}"
        )
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Verification error: {e}", exc_info=True)
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


# ========================================
# PROFILE MANAGEMENT
# ========================================

@app.route('/v1/profile/<user_uid>', methods=['GET'])
@require_api_key
@handle_errors
def get_user_profile(user_uid: str):
    """Get user behavioral profile"""
    merchant_id = request.merchant_id
    
    profile = ProfileDB.get_profile(merchant_id, user_uid)
    
    if not profile:
        return jsonify({
            'error': 'Profile not found'
        }), 404
    
    # Remove sensitive internal data
    safe_profile = {
        'user_uid': profile['user_uid'],
        'trust_score': profile.get('trust_score', 100),
        'is_locked': profile.get('is_locked', False),
        'total_verifications': profile.get('total_verifications', 0),
        'created_at': profile.get('created_at'),
        'last_session': profile.get('last_session_timestamp')
    }
    
    return jsonify(safe_profile), 200


@app.route('/v1/profile/<user_uid>/reset', methods=['POST'])
@require_api_key
@handle_errors
def reset_user_profile(user_uid: str):
    """Reset user behavioral profile (admin action)"""
    merchant_id = request.merchant_id
    
    profile = ProfileDB.get_profile(merchant_id, user_uid)
    
    if not profile:
        return jsonify({
            'error': 'Profile not found'
        }), 404
    
    # Reset to defaults
    ProfileDB.update_profile(profile['id'], {
        'baseline_stats': {},
        'trust_score': 100,
        'is_locked': False,
        'failed_attempts': 0,
        'known_fingerprints': []
    })
    
    logger.info(f"Profile reset: {user_uid}")
    
    return jsonify({
        'success': True,
        'message': 'Profile reset successfully'
    }), 200


# ========================================
# ACCOUNT RECOVERY
# ========================================

@app.route('/v1/recover/request', methods=['POST'])
@limiter.limit("5 per hour")
@require_api_key
@handle_errors
def request_recovery():
    """
    Request account unlock via email OTP
    
    Request Body:
        {
            "user_uid": "user_12345",
            "email": "user@example.com"
        }
    """
    merchant_id = request.merchant_id
    data = request.get_json()
    
    user_uid = data.get('user_uid')
    email = data.get('email')
    
    if not user_uid or not email:
        return jsonify({
            'error': 'Missing required fields'
        }), 400
    
    # Get profile
    profile = ProfileDB.get_profile(merchant_id, user_uid)
    
    if not profile:
        return jsonify({
            'error': 'Profile not found'
        }), 404
    
    if not profile.get('is_locked'):
        return jsonify({
            'error': 'Account is not locked'
        }), 400
    
    # Generate and send OTP
    success = otp_service.send_otp(email, user_uid)
    
    if success:
        logger.info(f"Recovery OTP sent: {user_uid}")
        return jsonify({
            'success': True,
            'message': 'Recovery code sent to email'
        }), 200
    else:
        return jsonify({
            'error': 'Failed to send recovery email'
        }), 500


@app.route('/v1/recover/verify', methods=['POST'])
@limiter.limit("10 per hour")
@require_api_key
@handle_errors
def verify_recovery():
    """
    Verify OTP and unlock account
    
    Request Body:
        {
            "user_uid": "user_12345",
            "otp": "123456"
        }
    """
    merchant_id = request.merchant_id
    data = request.get_json()
    
    user_uid = data.get('user_uid')
    otp_code = data.get('otp')
    
    if not user_uid or not otp_code:
        return jsonify({
            'error': 'Missing required fields'
        }), 400
    
    # Verify OTP
    if otp_service.verify_otp(user_uid, otp_code):
        # Get profile
        profile = ProfileDB.get_profile(merchant_id, user_uid)
        
        if profile:
            # Unlock account
            ProfileDB.unlock_profile(profile['id'])
            
            # Log recovery
            LogDB.create_log(merchant_id, {
                'user_uid': user_uid,
                'event_type': 'account_recovery',
                'ip_address': request.remote_addr
            })
            
            logger.info(f"Account unlocked: {user_uid}")
            
            return jsonify({
                'success': True,
                'message': 'Account unlocked successfully'
            }), 200
    
    return jsonify({
        'success': False,
        'error': 'Invalid or expired code'
    }), 401


# ========================================
# ANALYTICS & REPORTING
# ========================================

@app.route('/v1/analytics/summary', methods=['GET'])
@require_api_key
@handle_errors
def get_analytics_summary():
    """Get merchant analytics summary"""
    merchant_id = request.merchant_id
    
    # Get stats from database
    db = get_db()
    
    # Count profiles
    profiles_count = len(list(
        db.collection(Collections.PROFILES)
        .where('merchant_id', '==', merchant_id)
        .stream()
    ))
    
    # Get recent logs
    recent_logs = LogDB.get_recent_logs(merchant_id, limit=100)
    
    # Calculate statistics
    total_verifications = len(recent_logs)
    threats_blocked = len([l for l in recent_logs if l.get('decision') == 'LOCK'])
    
    risk_scores = [l.get('risk_score', 0) for l in recent_logs]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    
    return jsonify({
        'total_protected_users': profiles_count,
        'total_verifications': total_verifications,
        'threats_blocked': threats_blocked,
        'average_risk_score': round(avg_risk, 2),
        'timestamp': datetime.utcnow().isoformat()
    }), 200


# ========================================
# ERROR HANDLERS
# ========================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'status': 404
    }), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({
        'error': 'Internal server error',
        'status': 500
    }), 500


@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'status': 429
    }), 429


# ========================================
# STARTUP
# ========================================

if __name__ == '__main__':
    port = int(os.getenv('API_PORT', 5001))
    host = os.getenv('API_HOST', '0.0.0.0')
    debug = os.getenv('ENV', 'production') != 'production'
    
    logger.info(f"🚀 AuthGuard Intelligence API starting on {host}:{port}")
    logger.info(f"Environment: {os.getenv('ENV', 'production')}")
    logger.info(f"Debug mode: {debug}")
    
    # Initialize database connection
    try:
        get_db()
        logger.info("✅ Database connection established")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
    
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )