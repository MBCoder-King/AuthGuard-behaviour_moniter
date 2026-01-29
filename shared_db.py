"""
AuthGuard Enterprise - Shared Database Module
Handles Firebase Firestore connections with connection pooling and caching
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from functools import wraps

import firebase_admin
from firebase_admin import credentials, firestore, auth
from google.cloud.firestore_v1 import DocumentReference, CollectionReference
from google.cloud.firestore_v1.base_query import FieldFilter
from dotenv import load_dotenv
import redis

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Singleton instances
_db_instance: Optional[firestore.Client] = None
_redis_instance: Optional[redis.Redis] = None


class DatabaseError(Exception):
    """Custom exception for database errors"""
    pass


class CacheManager:
    """Redis cache manager for high-performance operations"""
    
    def __init__(self):
        self.redis_client = self._init_redis()
        self.default_ttl = int(os.getenv('REDIS_CACHE_TTL', 3600))
    
    def _init_redis(self) -> redis.Redis:
        """Initialize Redis connection"""
        try:
            client = redis.Redis(
                host=os.getenv('REDIS_HOST', 'localhost'),
                port=int(os.getenv('REDIS_PORT', 6379)),
                password=os.getenv('REDIS_PASSWORD', ''),
                db=int(os.getenv('REDIS_DB', 0)),
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            client.ping()
            logger.info("✅ Redis cache connected successfully")
            return client
        except Exception as e:
            logger.warning(f"⚠️ Redis connection failed: {e}. Cache disabled.")
            return None
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.redis_client:
            return None
        try:
            value = self.redis_client.get(key)
            if value:
                return json.loads(value)
        except Exception as e:
            logger.error(f"Cache get error: {e}")
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        if not self.redis_client:
            return False
        try:
            ttl = ttl or self.default_ttl
            self.redis_client.setex(key, ttl, json.dumps(value))
            return True
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self.redis_client:
            return False
        try:
            self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False
    
    def invalidate_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        if not self.redis_client:
            return 0
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys)
        except Exception as e:
            logger.error(f"Cache invalidate error: {e}")
        return 0


def init_firebase() -> firestore.Client:
    """
    Initialize Firebase Admin SDK and return Firestore client
    Uses singleton pattern to prevent multiple initializations
    """
    global _db_instance
    
    if _db_instance:
        return _db_instance
    
    cred_path = os.getenv('FIREBASE_CREDENTIALS', 'serviceAccountKey.json')
    
    # Check if credentials file exists
    if not os.path.exists(cred_path):
        error_msg = (
            f"❌ ERROR: Firebase credentials file not found at '{cred_path}'\n"
            f"Please download it from Firebase Console:\n"
            f"Project Settings → Service Accounts → Generate New Private Key"
        )
        logger.error(error_msg)
        raise DatabaseError(error_msg)
    
    try:
        # Initialize Firebase Admin
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred, {
            'projectId': os.getenv('FIREBASE_PROJECT_ID'),
            'databaseURL': os.getenv('FIREBASE_DATABASE_URL')
        })
        
        _db_instance = firestore.client()
        logger.info("✅ Firebase Firestore connected successfully")
        
        return _db_instance
        
    except ValueError as e:
        # App already initialized
        if "already exists" in str(e):
            _db_instance = firestore.client()
            logger.info("✅ Firebase already initialized, reusing instance")
            return _db_instance
        raise DatabaseError(f"Firebase initialization error: {e}")
    
    except Exception as e:
        logger.error(f"❌ Firebase connection failed: {e}")
        raise DatabaseError(f"Failed to connect to Firebase: {e}")


def get_db() -> firestore.Client:
    """Get Firestore database instance"""
    if not _db_instance:
        return init_firebase()
    return _db_instance


def get_cache() -> CacheManager:
    """Get Redis cache manager instance"""
    global _redis_instance
    if not _redis_instance:
        _redis_instance = CacheManager()
    return _redis_instance


# ========================================
# COLLECTION HELPERS
# ========================================

class Collections:
    """Collection name constants"""
    MERCHANTS = 'merchants'
    PROFILES = 'profiles'
    LOGS = 'logs'
    SESSIONS = 'sessions'
    ALERTS = 'alerts'
    API_KEYS = 'api_keys'
    ANALYTICS = 'analytics'
    SUBSCRIPTIONS = 'subscriptions'
    AUDIT_TRAIL = 'audit_trail'


def cached_query(ttl: int = 300):
    """Decorator to cache Firestore query results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            cache_key = f"query:{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Try to get from cache
            cache = get_cache()
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache HIT: {cache_key}")
                return cached_result
            
            # Execute query
            result = func(*args, **kwargs)
            
            # Store in cache
            cache.set(cache_key, result, ttl)
            logger.debug(f"Cache MISS: {cache_key}")
            
            return result
        return wrapper
    return decorator


# ========================================
# MERCHANT OPERATIONS
# ========================================

class MerchantDB:
    """Database operations for merchants"""
    
    @staticmethod
    def create_merchant(data: Dict[str, Any]) -> str:
        """Create a new merchant account"""
        db = get_db()
        
        # Add timestamps
        data['created_at'] = firestore.SERVER_TIMESTAMP
        data['updated_at'] = firestore.SERVER_TIMESTAMP
        data['status'] = 'active'
        data['credits'] = data.get('credits', 10000)
        
        # Create document
        doc_ref = db.collection(Collections.MERCHANTS).add(data)
        merchant_id = doc_ref[1].id
        
        logger.info(f"✅ Merchant created: {merchant_id}")
        return merchant_id
    
    @staticmethod
    @cached_query(ttl=600)
    def get_merchant_by_email(email: str) -> Optional[Dict[str, Any]]:
        """Get merchant by email"""
        db = get_db()
        
        query = db.collection(Collections.MERCHANTS).where(
            filter=FieldFilter('email', '==', email)
        ).limit(1).stream()
        
        for doc in query:
            return {'id': doc.id, **doc.to_dict()}
        return None
    
    @staticmethod
    @cached_query(ttl=300)
    def get_merchant_by_api_key(api_key: str) -> Optional[Dict[str, Any]]:
        """Get merchant by API key"""
        db = get_db()
        
        query = db.collection(Collections.MERCHANTS).where(
            filter=FieldFilter('api_key', '==', api_key)
        ).limit(1).stream()
        
        for doc in query:
            return {'id': doc.id, **doc.to_dict()}
        return None
    
    @staticmethod
    def update_merchant(merchant_id: str, data: Dict[str, Any]) -> bool:
        """Update merchant data"""
        db = get_db()
        cache = get_cache()
        
        data['updated_at'] = firestore.SERVER_TIMESTAMP
        
        db.collection(Collections.MERCHANTS).document(merchant_id).update(data)
        
        # Invalidate cache
        cache.invalidate_pattern(f"query:get_merchant*")
        
        logger.info(f"✅ Merchant updated: {merchant_id}")
        return True
    
    @staticmethod
    def deduct_credits(merchant_id: str, amount: int = 1) -> bool:
        """Deduct credits from merchant account"""
        db = get_db()
        cache = get_cache()
        
        merchant_ref = db.collection(Collections.MERCHANTS).document(merchant_id)
        
        try:
            merchant_ref.update({
                'credits': firestore.Increment(-amount)
            })
            
            # Invalidate cache
            cache.delete(f"merchant:{merchant_id}:credits")
            
            return True
        except Exception as e:
            logger.error(f"Failed to deduct credits: {e}")
            return False


# ========================================
# PROFILE OPERATIONS
# ========================================

class ProfileDB:
    """Database operations for user behavioral profiles"""
    
    @staticmethod
    def create_profile(merchant_id: str, user_uid: str, data: Dict[str, Any]) -> str:
        """Create a new user profile"""
        db = get_db()
        
        profile_data = {
            'merchant_id': merchant_id,
            'user_uid': user_uid,
            'created_at': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP,
            'baseline_stats': data.get('baseline_stats', {}),
            'trust_score': 100,
            'is_locked': False,
            'total_verifications': 0,
            'failed_attempts': 0
        }
        
        doc_ref = db.collection(Collections.PROFILES).add(profile_data)
        profile_id = doc_ref[1].id
        
        logger.info(f"✅ Profile created: {profile_id}")
        return profile_id
    
    @staticmethod
    @cached_query(ttl=180)
    def get_profile(merchant_id: str, user_uid: str) -> Optional[Dict[str, Any]]:
        """Get user profile"""
        db = get_db()
        
        query = db.collection(Collections.PROFILES).where(
            filter=FieldFilter('merchant_id', '==', merchant_id)
        ).where(
            filter=FieldFilter('user_uid', '==', user_uid)
        ).limit(1).stream()
        
        for doc in query:
            return {'id': doc.id, **doc.to_dict()}
        return None
    
    @staticmethod
    def update_profile(profile_id: str, data: Dict[str, Any]) -> bool:
        """Update profile data"""
        db = get_db()
        cache = get_cache()
        
        data['updated_at'] = firestore.SERVER_TIMESTAMP
        
        db.collection(Collections.PROFILES).document(profile_id).update(data)
        
        # Invalidate cache
        cache.invalidate_pattern(f"query:get_profile*")
        
        return True
    
    @staticmethod
    def lock_profile(profile_id: str, reason: str) -> bool:
        """Lock a user profile"""
        return ProfileDB.update_profile(profile_id, {
            'is_locked': True,
            'locked_reason': reason,
            'locked_at': firestore.SERVER_TIMESTAMP
        })
    
    @staticmethod
    def unlock_profile(profile_id: str) -> bool:
        """Unlock a user profile"""
        return ProfileDB.update_profile(profile_id, {
            'is_locked': False,
            'locked_reason': None,
            'unlocked_at': firestore.SERVER_TIMESTAMP,
            'trust_score': 100
        })


# ========================================
# LOG OPERATIONS
# ========================================

class LogDB:
    """Database operations for security logs"""
    
    @staticmethod
    def create_log(merchant_id: str, data: Dict[str, Any]) -> str:
        """Create a security log entry"""
        db = get_db()
        
        log_data = {
            'merchant_id': merchant_id,
            'timestamp': firestore.SERVER_TIMESTAMP,
            **data
        }
        
        doc_ref = db.collection(Collections.LOGS).add(log_data)
        return doc_ref[1].id
    
    @staticmethod
    def get_recent_logs(merchant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent logs for a merchant"""
        db = get_db()
        
        query = db.collection(Collections.LOGS).where(
            filter=FieldFilter('merchant_id', '==', merchant_id)
        ).order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit).stream()
        
        return [{'id': doc.id, **doc.to_dict()} for doc in query]


# ========================================
# HEALTH CHECK
# ========================================

def health_check() -> Dict[str, Any]:
    """Check database and cache connectivity"""
    status = {
        'firestore': False,
        'redis': False,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    # Check Firestore
    try:
        db = get_db()
        db.collection('_health_check').limit(1).get()
        status['firestore'] = True
    except Exception as e:
        logger.error(f"Firestore health check failed: {e}")
    
    # Check Redis
    try:
        cache = get_cache()
        if cache.redis_client and cache.redis_client.ping():
            status['redis'] = True
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
    
    return status


if __name__ == "__main__":
    # Test database connection
    print("Testing database connections...")
    status = health_check()
    print(f"Firestore: {'✅' if status['firestore'] else '❌'}")
    print(f"Redis: {'✅' if status['redis'] else '❌'}")