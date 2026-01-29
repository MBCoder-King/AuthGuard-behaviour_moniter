import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '../infrastructure/.env'))

# Connection Pool for High Concurrency (API needs to handle thousands of requests/sec)
pg_pool = psycopg2.pool.ThreadedConnectionPool(
    1, 50,
    dsn=os.getenv("DATABASE_URL"),
    sslmode='require'
)

def get_db():
    return pg_pool.getconn()

def return_db(conn):
    if conn:
        pg_pool.putconn(conn)

def fetch_user_profile(merchant_id, user_uid):
    """
    Fetches the 'Digital DNA' baseline for a user.
    """
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Optimized query with Index scan
        cur.execute("""
            SELECT baseline_stats, trust_score, is_locked, locked_until 
            FROM behavior_profiles 
            WHERE merchant_id = %s AND user_uid = %s
        """, (merchant_id, user_uid))
        return cur.fetchone()
    finally:
        return_db(conn)

def log_event(merchant_id, user_uid, event_type, score):
    """
    Async logging of security events (Fire & Forget style recommended for prod).
    """
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO auth_logs (merchant_id, user_uid, event_type, risk_score)
            VALUES (%s, %s, %s, %s)
        """, (merchant_id, user_uid, event_type, score))
        conn.commit()
    finally:
        return_db(conn)