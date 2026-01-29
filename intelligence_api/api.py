from flask import Flask, request, jsonify
from middleware import require_api_key
from db import fetch_user_profile, log_event, get_db, return_db
from core_logic import analyze_risk
import json
import redis
import os
from otp import generate_otp, send_recovery_email

app = Flask(__name__)

# ============================================
# REDIS CLIENT CONFIGURATION
# ============================================
try:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=int(os.getenv('REDIS_DB', 0)),
        decode_responses=True,  # Automatically decode bytes to strings
        socket_connect_timeout=5,
        socket_keepalive=True,
        health_check_interval=30
    )
    # Test connection
    redis_client.ping()
    print("✓ Redis connected successfully")
except redis.ConnectionError as e:
    print(f"✗ Redis connection failed: {e}")
    redis_client = None
except Exception as e:
    print(f"✗ Redis initialization error: {e}")
    redis_client = None


# ============================================
# HELPER FUNCTIONS FOR OTP MANAGEMENT
# ============================================
def store_otp(uid, code, expiry_seconds=300):
    """
    Store OTP in Redis with automatic expiration.
    
    Args:
        uid (str): User unique identifier
        code (str): 6-digit OTP code
        expiry_seconds (int): TTL in seconds (default: 5 minutes)
    
    Returns:
        bool: True if stored successfully, False otherwise
    """
    if not redis_client:
        print(f"⚠️  Redis unavailable, OTP storage failed for {uid}")
        return False
    
    try:
        key = f"otp:{uid}"
        redis_client.setex(key, expiry_seconds, code)
        print(f"✓ OTP stored for {uid}, expires in {expiry_seconds}s")
        return True
    except redis.RedisError as e:
        print(f"✗ Failed to store OTP for {uid}: {e}")
        return False


def verify_otp(uid, user_code):
    """
    Verify OTP code and delete it from Redis on success.
    
    Args:
        uid (str): User unique identifier
        user_code (str): OTP code provided by user
    
    Returns:
        bool: True if OTP is valid, False otherwise
    """
    if not redis_client:
        print(f"⚠️  Redis unavailable, OTP verification failed for {uid}")
        return False
    
    try:
        key = f"otp:{uid}"
        stored_code = redis_client.get(key)
        
        # Check if OTP exists and matches
        if stored_code is None:
            print(f"⚠️  OTP expired or not found for {uid}")
            return False
        
        # Compare codes (both are strings due to decode_responses=True)
        if stored_code == str(user_code).strip():
            # Delete OTP after successful verification
            redis_client.delete(key)
            print(f"✓ OTP verified successfully for {uid}")
            return True
        else:
            print(f"✗ OTP mismatch for {uid}")
            return False
            
    except redis.RedisError as e:
        print(f"✗ OTP verification error for {uid}: {e}")
        return False


def get_otp_attempts(uid, max_attempts=5):
    """
    Track OTP verification attempts to prevent brute force.
    
    Args:
        uid (str): User unique identifier
        max_attempts (int): Maximum allowed attempts
    
    Returns:
        dict: {'allowed': bool, 'attempts': int, 'remaining': int}
    """
    if not redis_client:
        return {'allowed': True, 'attempts': 0, 'remaining': max_attempts}
    
    try:
        attempt_key = f"otp_attempts:{uid}"
        attempts = int(redis_client.get(attempt_key) or 0)
        remaining = max_attempts - attempts
        
        return {
            'allowed': remaining > 0,
            'attempts': attempts,
            'remaining': max(0, remaining)
        }
    except Exception as e:
        print(f"✗ Error checking OTP attempts for {uid}: {e}")
        return {'allowed': True, 'attempts': 0, 'remaining': max_attempts}


def increment_otp_attempts(uid, expiry_seconds=900):
    """
    Increment OTP verification attempts counter (15 min lockout).
    
    Args:
        uid (str): User unique identifier
        expiry_seconds (int): How long to track attempts
    """
    if not redis_client:
        return
    
    try:
        attempt_key = f"otp_attempts:{uid}"
        redis_client.incr(attempt_key)
        redis_client.expire(attempt_key, expiry_seconds)
    except redis.RedisError as e:
        print(f"✗ Error incrementing OTP attempts for {uid}: {e}")


# ============================================
# API ROUTES
# ============================================

@app.route('/v1/session/init', methods=['POST'])
@require_api_key
def init_session():
    """
    Called when a user logs in. Returns their current status.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        uid = data.get('user_uid')
        if not uid:
            return jsonify({"error": "Missing user_uid"}), 400
        
        profile = fetch_user_profile(request.merchant_id, uid)
        
        if profile and profile.get('is_locked'):
            return jsonify({
                "status": "LOCKED",
                "locked_until": profile['locked_until']
            }), 403
            
        return jsonify({
            "status": "ACTIVE",
            "session_id": f"sess_{uid}_{int(request.timestamp)}"
        }), 200
        
    except Exception as e:
        print(f"✗ Error in init_session: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/v1/verify', methods=['POST'])
@require_api_key
def verify_behavior():
    """
    The heartbeat. SDK sends telemetry here every 5s.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        uid = data.get('user_uid')
        telemetry = data.get('telemetry', {})
        
        if not uid:
            return jsonify({"error": "Missing user_uid"}), 400
        
        # 1. Get Baseline
        profile = fetch_user_profile(request.merchant_id, uid)
        
        if not profile or not profile.get('baseline_stats'):
            # Cold Start: Building baseline
            log_event(request.merchant_id, uid, "BASELINE_BUILD", 0)
            return jsonify({
                "decision": "ALLOW",
                "risk_score": 0,
                "reason": "Training Phase - Baseline Building"
            }), 200
        
        # 2. Analyze Risk
        risk_score, reason = analyze_risk(telemetry, profile)
        
        # 3. Make Decision
        decision = "ALLOW"
        if risk_score > 75:
            decision = "LOCK"
        elif risk_score > 40:
            decision = "VERIFY"  # Trigger OTP
        
        # 4. Log Event
        log_event(request.merchant_id, uid, decision, risk_score)
        
        # 5. Lock Account if needed
        if decision == "LOCK":
            conn = get_db()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute("""
                        UPDATE behavior_profiles 
                        SET is_locked = TRUE, 
                            locked_until = NOW() + INTERVAL '1 hour',
                            trust_score = 0
                        WHERE merchant_id = %s AND user_uid = %s
                    """, (request.merchant_id, uid))
                    conn.commit()
                    cur.close()
                except Exception as db_error:
                    print(f"✗ Failed to lock account: {db_error}")
                finally:
                    return_db(conn)
        
        return jsonify({
            "decision": decision,
            "risk_score": risk_score,
            "reason": reason
        }), 200
        
    except Exception as e:
        print(f"✗ Error in verify_behavior: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/v1/recover/request', methods=['POST'])
@require_api_key
def request_unlock():
    """
    Request an OTP code to unlock a locked account.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        uid = data.get('user_uid')
        email = data.get('email')
        
        if not uid or not email:
            return jsonify({"error": "Missing user_uid or email"}), 400
        
        # Validate email format
        if '@' not in email or len(email) < 5:
            return jsonify({"error": "Invalid email format"}), 400
        
        # 1. Generate OTP Code
        code = generate_otp()
        
        # 2. Store in Redis (5 minute expiry)
        if not store_otp(uid, code, expiry_seconds=300):
            return jsonify({"error": "OTP service unavailable"}), 503
        
        # 3. Send Email
        success = send_recovery_email(email, code)
        
        if success:
            log_event(request.merchant_id, uid, "OTP_REQUESTED", 0)
            return jsonify({
                "success": True,
                "message": "OTP sent successfully",
                "expires_in": 300
            }), 200
        else:
            # Clean up Redis if email send failed
            if redis_client:
                redis_client.delete(f"otp:{uid}")
            log_event(request.merchant_id, uid, "OTP_SEND_FAILED", 0)
            return jsonify({"error": "Failed to send email"}), 500
        
    except Exception as e:
        print(f"✗ Error in request_unlock: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/v1/recover/verify', methods=['POST'])
@require_api_key
def verify_unlock():
    """
    Verify OTP code and unlock the account.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        uid = data.get('user_uid')
        user_code = data.get('otp')
        
        if not uid or not user_code:
            return jsonify({"error": "Missing user_uid or otp"}), 400
        
        # Check brute force attempts
        attempts_info = get_otp_attempts(uid, max_attempts=5)
        if not attempts_info['allowed']:
            return jsonify({
                "success": False,
                "error": "Too many attempts. Please try again later.",
                "remaining_attempts": 0
            }), 429  # Too Many Requests
        
        # Verify OTP
        is_valid = verify_otp(uid, user_code)
        
        if is_valid:
            # 2. Unlock Account in Database
            conn = get_db()
            if not conn:
                return jsonify({"error": "Database unavailable"}), 503
            
            try:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE behavior_profiles 
                    SET is_locked = FALSE, 
                        trust_score = 90, 
                        locked_until = NULL
                    WHERE merchant_id = %s AND user_uid = %s
                """, (request.merchant_id, uid))
                conn.commit()
                cur.close()
                
                # Clear attempts counter on success
                if redis_client:
                    redis_client.delete(f"otp_attempts:{uid}")
                
                log_event(request.merchant_id, uid, "ACCOUNT_UNLOCKED", 0)
                return jsonify({
                    "success": True,
                    "message": "Account unlocked successfully"
                }), 200
                
            except Exception as db_error:
                print(f"✗ Database error during unlock: {db_error}")
                return jsonify({"error": "Failed to unlock account"}), 500
            finally:
                return_db(conn)
        else:
            # Invalid OTP - increment attempts
            increment_otp_attempts(uid)
            attempts_info = get_otp_attempts(uid)
            
            log_event(request.merchant_id, uid, "OTP_VERIFICATION_FAILED", 0)
            return jsonify({
                "success": False,
                "error": "Invalid OTP code",
                "remaining_attempts": attempts_info['remaining']
            }), 400
        
    except Exception as e:
        print(f"✗ Error in verify_unlock: {e}")
        return jsonify({"error": "Internal server error"}), 500


# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request"}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint Not Found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error"}), 500


# ============================================
# SHUTDOWN HANDLER
# ============================================

@app.teardown_appcontext
def close_redis(error):
    """Close Redis connection on app shutdown."""
    if redis_client:
        try:
            redis_client.close()
            print("✓ Redis connection closed")
        except Exception as e:
            print(f"✗ Error closing Redis: {e}")


# ============================================
# APPLICATION STARTUP
# ============================================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)