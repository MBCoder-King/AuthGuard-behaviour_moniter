from functools import wraps
from flask import request, jsonify
from db import get_db, return_db

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        
        if not api_key:
            return jsonify({"error": "Missing API Key"}), 401
        
        conn = get_db()
        try:
            cur = conn.cursor()
            # Check key and get Merchant ID
            cur.execute("SELECT id, credits_balance FROM merchants WHERE api_key = %s", (api_key,))
            merchant = cur.fetchone()
            
            if not merchant:
                return jsonify({"error": "Invalid API Key"}), 403
            
            merchant_id, balance = merchant
            
            if balance <= 0:
                return jsonify({"error": "Payment Required: Zero Credits"}), 402

            # Attach merchant_id to the request object for the route to use
            request.merchant_id = merchant_id
            
        finally:
            return_db(conn)
            
        return f(*args, **kwargs)
    return decorated_function