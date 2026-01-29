import os
import secrets
import sys
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

# Add root directory to path to import shared_db
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_db import get_db

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev_key')

# --- MIDDLEWARE ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'merchant_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = get_db()
        company = request.form['company']
        email = request.form['email']
        password = request.form['password']
        
        # Check if email exists (Firestore Query)
        users_ref = db.collection('merchants')
        query = users_ref.where('email', '==', email).stream()
        if any(query):
            flash("Email already registered.", "error")
            return redirect(url_for('register'))
        
        # Create Merchant Document
        new_api_key = f"ag_live_{secrets.token_urlsafe(24)}"
        merchant_data = {
            "company_name": company,
            "email": email,
            "password_hash": generate_password_hash(password),
            "api_key": new_api_key,
            "credits": 10000,
            "created_at": firestore.SERVER_TIMESTAMP
        }
        
        # Add to Firestore (Auto-ID)
        db.collection('merchants').add(merchant_data)
        
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        db = get_db()
        email = request.form['email']
        password = request.form['password']
        
        # Find user by email
        users_ref = db.collection('merchants')
        query = users_ref.where('email', '==', email).limit(1).stream()
        
        merchant = None
        merchant_id = None
        for doc in query:
            merchant = doc.to_dict()
            merchant_id = doc.id
            
        if merchant and check_password_hash(merchant['password_hash'], password):
            session['merchant_id'] = merchant_id
            session['company_name'] = merchant['company_name']
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "error")
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    mid = session['merchant_id']
    
    # 1. Get Merchant Info
    merchant_doc = db.collection('merchants').document(mid).get()
    merchant_data = merchant_doc.to_dict()
    
    # 2. Get Stats (Count Documents in Subcollection)
    # Note: Firestore count is expensive, in prod use distributed counters
    profiles_ref = db.collection('profiles').where('merchant_id', '==', mid)
    profiles = list(profiles_ref.stream())
    user_count = len(profiles)
    
    # 3. Get Recent Logs
    logs_ref = db.collection('logs').where('merchant_id', '==', mid)\
                 .order_by('timestamp', direction=firestore.Query.DESCENDING).limit(10)
    logs = [doc.to_dict() for doc in logs_ref.stream()]
    
    return render_template('dashboard.html', merchant=merchant_data, user_count=user_count, logs=logs)

@app.route('/api/rotate-key', methods=['POST'])
@login_required
def rotate_key():
    db = get_db()
    mid = session['merchant_id']
    new_key = f"ag_live_{secrets.token_urlsafe(24)}"
    
    db.collection('merchants').document(mid).update({"api_key": new_key})
    
    return jsonify({"success": True, "new_key": new_key})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)