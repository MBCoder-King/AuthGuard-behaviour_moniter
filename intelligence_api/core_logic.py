"""
AuthGuard Enterprise - Core AI & Risk Analysis Engine
Advanced behavioral biometrics and anomaly detection algorithms
"""

import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from scipy import stats
import joblib
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========================================
# CONFIGURATION
# ========================================

class RiskConfig:
    """Risk analysis configuration constants"""
    
    # Weight distribution for risk factors
    WEIGHTS = {
        'typing_dynamics': 0.35,      # Keystroke timing patterns
        'mouse_dynamics': 0.25,        # Mouse movement entropy
        'behavioral_deviation': 0.20,  # Statistical deviation from baseline
        'geo_velocity': 0.10,          # Impossible travel detection
        'device_fingerprint': 0.10     # Device consistency check
    }
    
    # Thresholds
    ENTROPY_THRESHOLD_LOW = 0.8      # Below = bot
    ENTROPY_THRESHOLD_HIGH = 2.5     # Above = human
    Z_SCORE_THRESHOLD = 2.5          # Statistical anomaly threshold
    VELOCITY_MAX_KMH = 1000          # Maximum realistic travel speed
    
    # Risk score ranges
    RISK_LOW = 40
    RISK_HIGH = 80
    
    # Isolation Forest parameters
    ISOLATION_CONTAMINATION = 0.1
    ISOLATION_N_ESTIMATORS = 100


# ========================================
# STATISTICAL ANALYSIS
# ========================================

def calculate_z_score(current_val: float, baseline_mean: float, baseline_std: float) -> float:
    """
    Calculate Z-score (standard deviations from mean)
    
    Z-score measures how many standard deviations an observation is from the mean.
    |Z| > 2.5 indicates 98.76% confidence that this is anomalous behavior.
    
    Args:
        current_val: Current measured value
        baseline_mean: Historical average for this user
        baseline_std: Historical standard deviation
    
    Returns:
        Z-score (absolute value)
    """
    if baseline_std == 0 or baseline_std is None:
        return 0.0
    
    try:
        z_score = abs((current_val - baseline_mean) / baseline_std)
        return round(z_score, 2)
    except (TypeError, ZeroDivisionError):
        return 0.0


def calculate_mad_score(current_val: float, baseline_data: List[float]) -> float:
    """
    Calculate Median Absolute Deviation score (robust to outliers)
    
    More robust than Z-score for non-normal distributions.
    
    Args:
        current_val: Current measured value
        baseline_data: Historical data points
    
    Returns:
        MAD score
    """
    if not baseline_data or len(baseline_data) < 3:
        return 0.0
    
    try:
        median = np.median(baseline_data)
        mad = np.median(np.abs(np.array(baseline_data) - median))
        
        if mad == 0:
            return 0.0
        
        mad_score = abs((current_val - median) / mad)
        return round(mad_score, 2)
    except Exception as e:
        logger.error(f"MAD calculation error: {e}")
        return 0.0


def calculate_percentile_rank(current_val: float, baseline_data: List[float]) -> float:
    """
    Calculate percentile rank of current value in baseline distribution
    
    Returns:
        Percentile (0-100)
    """
    if not baseline_data:
        return 50.0
    
    try:
        percentile = stats.percentileofscore(baseline_data, current_val)
        return round(percentile, 1)
    except Exception:
        return 50.0


# ========================================
# ENTROPY & BOT DETECTION
# ========================================

def calculate_shannon_entropy(data: List[float], bins: int = 10) -> float:
    """
    Calculate Shannon Entropy to measure randomness/disorder
    
    Entropy = -Σ(p(x) * log(p(x)))
    
    Low entropy (< 0.5) = Predictable/Regular = Bot
    High entropy (> 2.0) = Random/Chaotic = Human
    
    Args:
        data: List of numeric values
        bins: Number of histogram bins
    
    Returns:
        Entropy value (0 = perfectly ordered, higher = more random)
    """
    if not data or len(data) < 3:
        return 0.5  # Default low entropy
    
    try:
        # Create histogram
        hist, _ = np.histogram(data, bins=bins, density=True)
        
        # Remove zero probabilities
        hist = hist[hist > 0]
        
        # Calculate entropy
        entropy = -np.sum(hist * np.log2(hist + 1e-10))
        
        return round(entropy, 3)
    except Exception as e:
        logger.error(f"Entropy calculation error: {e}")
        return 0.5


def detect_bot_movement(mouse_path: List[Dict[str, float]]) -> Tuple[float, List[str]]:
    """
    Analyze mouse movement patterns to detect bot/automation
    
    Bots create perfectly straight lines or mathematically regular patterns.
    Humans create organic curves with natural variation.
    
    Args:
        mouse_path: List of {x, y, t} coordinates
    
    Returns:
        Tuple of (entropy_score, detected_anomalies)
    """
    if not mouse_path or len(mouse_path) < 5:
        return 0.5, ["INSUFFICIENT_DATA"]
    
    anomalies = []
    
    try:
        # Extract coordinates
        points = [(p['x'], p['y']) for p in mouse_path]
        
        # 1. Calculate angular entropy
        angles = []
        for i in range(1, len(points) - 1):
            p1, p2, p3 = points[i-1], points[i], points[i+1]
            
            # Vector angles
            angle1 = np.arctan2(p2[1] - p1[1], p2[0] - p1[0])
            angle2 = np.arctan2(p3[1] - p2[1], p3[0] - p2[0])
            
            # Angle change
            angle_diff = angle2 - angle1
            angles.append(angle_diff)
        
        entropy = calculate_shannon_entropy(angles, bins=12)
        
        # 2. Check for perfectly straight lines
        if len(points) > 10:
            x_coords = [p[0] for p in points]
            y_coords = [p[1] for p in points]
            
            x_std = np.std(x_coords)
            y_std = np.std(y_coords)
            
            if x_std < 2 or y_std < 2:
                anomalies.append("STRAIGHT_LINE_MOVEMENT")
                entropy *= 0.5
        
        # 3. Check for identical intervals (robotic timing)
        if len(mouse_path) > 5:
            timestamps = [p['t'] for p in mouse_path]
            intervals = np.diff(timestamps)
            interval_std = np.std(intervals)
            
            if interval_std < 5:  # Less than 5ms variation
                anomalies.append("ROBOTIC_TIMING")
                entropy *= 0.5
        
        # 4. Check for teleportation (instantaneous jumps)
        for i in range(1, len(points)):
            distance = np.sqrt(
                (points[i][0] - points[i-1][0])**2 + 
                (points[i][1] - points[i-1][1])**2
            )
            
            if distance > 500:  # > 500px jump
                anomalies.append("MOUSE_TELEPORTATION")
        
        return round(entropy, 3), anomalies
        
    except Exception as e:
        logger.error(f"Bot detection error: {e}")
        return 0.5, ["ANALYSIS_ERROR"]


def detect_environment_anomalies(telemetry: Dict[str, Any]) -> List[str]:
    """
    Detect automation tools and suspicious environments
    
    Args:
        telemetry: Telemetry data from client
    
    Returns:
        List of detected anomalies
    """
    anomalies = []
    
    # Check for bot flags from client
    bot_flags = telemetry.get('bot_flags', [])
    anomalies.extend(bot_flags)
    
    # Check fingerprint
    fingerprint = telemetry.get('fingerprint', {})
    
    # Headless browser detection
    user_agent = fingerprint.get('userAgent', '')
    if 'HeadlessChrome' in user_agent or 'PhantomJS' in user_agent:
        anomalies.append("HEADLESS_BROWSER")
    
    # Invalid screen dimensions
    screen_res = fingerprint.get('screenRes', '0x0')
    if screen_res in ['0x0', '1x1']:
        anomalies.append("INVALID_SCREEN_DIMENSIONS")
    
    # Suspicious hardware
    cores = fingerprint.get('cores', 'unknown')
    if cores == 'unknown' or (isinstance(cores, int) and cores > 64):
        anomalies.append("SUSPICIOUS_HARDWARE")
    
    return list(set(anomalies))  # Remove duplicates


# ========================================
# TYPING DYNAMICS ANALYSIS
# ========================================

def analyze_typing_dynamics(telemetry: Dict[str, Any], profile: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
    """
    Analyze keystroke timing patterns
    
    Flight Time: Time between key presses (typing speed)
    Dwell Time: How long a key is held down
    
    Args:
        telemetry: Current session telemetry
        profile: User's baseline profile
    
    Returns:
        Tuple of (risk_score, metrics)
    """
    risk_score = 0.0
    metrics = {}
    
    baseline_stats = profile.get('baseline_stats', {})
    
    try:
        # Analyze flight times (inter-key intervals)
        flight_vec = telemetry.get('flight_vec', [])
        if flight_vec and 'flight_mean' in baseline_stats:
            current_flight_mean = np.mean(flight_vec)
            current_flight_std = np.std(flight_vec)
            
            flight_z = calculate_z_score(
                current_flight_mean,
                baseline_stats['flight_mean'],
                baseline_stats.get('flight_std', 10)
            )
            
            metrics['flight_z_score'] = flight_z
            metrics['flight_mean'] = round(current_flight_mean, 2)
            
            # High Z-score = anomalous typing speed
            if flight_z > RiskConfig.Z_SCORE_THRESHOLD:
                risk_addition = min(40, flight_z * 10)
                risk_score += risk_addition * RiskConfig.WEIGHTS['typing_dynamics']
        
        # Analyze dwell times (key hold duration)
        dwell_vec = telemetry.get('dwell_vec', [])
        if dwell_vec and 'dwell_mean' in baseline_stats:
            current_dwell_mean = np.mean(dwell_vec)
            
            dwell_z = calculate_z_score(
                current_dwell_mean,
                baseline_stats['dwell_mean'],
                baseline_stats.get('dwell_std', 5)
            )
            
            metrics['dwell_z_score'] = dwell_z
            metrics['dwell_mean'] = round(current_dwell_mean, 2)
            
            if dwell_z > RiskConfig.Z_SCORE_THRESHOLD:
                risk_addition = min(30, dwell_z * 8)
                risk_score += risk_addition * RiskConfig.WEIGHTS['typing_dynamics']
        
    except Exception as e:
        logger.error(f"Typing dynamics analysis error: {e}")
    
    return round(risk_score, 2), metrics


# ========================================
# GEO-VELOCITY ANALYSIS
# ========================================

def calculate_geo_velocity(
    prev_location: Dict[str, float],
    current_location: Dict[str, float],
    time_diff_seconds: float
) -> float:
    """
    Calculate travel velocity between two locations
    
    Uses Haversine formula to calculate distance between lat/lon coordinates
    
    Args:
        prev_location: {lat, lon} of previous session
        current_location: {lat, lon} of current session
        time_diff_seconds: Time between sessions
    
    Returns:
        Velocity in km/h
    """
    if time_diff_seconds <= 0:
        return 0.0
    
    try:
        # Haversine formula
        lat1, lon1 = prev_location['lat'], prev_location['lon']
        lat2, lon2 = current_location['lat'], current_location['lon']
        
        R = 6371  # Earth's radius in km
        
        dlat = np.radians(lat2 - lat1)
        dlon = np.radians(lon2 - lon1)
        
        a = (np.sin(dlat/2)**2 + 
             np.cos(np.radians(lat1)) * np.cos(np.radians(lat2)) * 
             np.sin(dlon/2)**2)
        
        c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1-a))
        distance_km = R * c
        
        # Calculate velocity
        time_hours = time_diff_seconds / 3600
        velocity_kmh = distance_km / time_hours
        
        return round(velocity_kmh, 2)
        
    except Exception as e:
        logger.error(f"Geo-velocity calculation error: {e}")
        return 0.0


def analyze_geo_anomalies(
    telemetry: Dict[str, Any],
    profile: Dict[str, Any]
) -> Tuple[float, Dict[str, Any]]:
    """
    Detect impossible travel patterns
    
    Args:
        telemetry: Current session data
        profile: User's profile with last known location
    
    Returns:
        Tuple of (risk_score, metrics)
    """
    risk_score = 0.0
    metrics = {}
    
    try:
        current_geo = telemetry.get('geo_location', {})
        last_geo = profile.get('last_geo_location', {})
        last_timestamp = profile.get('last_session_timestamp')
        
        if current_geo and last_geo and last_timestamp:
            # Calculate time difference
            current_time = datetime.utcnow()
            
            if isinstance(last_timestamp, str):
                last_time = datetime.fromisoformat(last_timestamp)
            else:
                last_time = last_timestamp
            
            time_diff = (current_time - last_time).total_seconds()
            
            # Calculate velocity
            velocity = calculate_geo_velocity(last_geo, current_geo, time_diff)
            
            metrics['velocity_kmh'] = velocity
            metrics['distance_km'] = round(velocity * (time_diff / 3600), 2)
            
            # Flag impossible travel
            if velocity > RiskConfig.VELOCITY_MAX_KMH:
                risk_score = 90 * RiskConfig.WEIGHTS['geo_velocity']
                metrics['impossible_travel'] = True
        
    except Exception as e:
        logger.error(f"Geo-analysis error: {e}")
    
    return round(risk_score, 2), metrics


# ========================================
# DEVICE FINGERPRINT ANALYSIS
# ========================================

def analyze_device_consistency(
    telemetry: Dict[str, Any],
    profile: Dict[str, Any]
) -> Tuple[float, Dict[str, Any]]:
    """
    Check if device fingerprint matches known profile
    
    Args:
        telemetry: Current session data
        profile: User's profile with known fingerprints
    
    Returns:
        Tuple of (risk_score, metrics)
    """
    risk_score = 0.0
    metrics = {}
    
    try:
        current_fp = telemetry.get('fingerprint', {})
        known_fps = profile.get('known_fingerprints', [])
        
        if not current_fp or not known_fps:
            return 0.0, metrics
        
        # Check if current fingerprint matches any known fingerprint
        is_match = False
        for known_fp in known_fps:
            match_score = 0
            total_checks = 0
            
            # Compare each attribute
            for key in ['screenRes', 'colorDepth', 'cores', 'timezone']:
                if key in current_fp and key in known_fp:
                    total_checks += 1
                    if current_fp[key] == known_fp[key]:
                        match_score += 1
            
            # If 75%+ attributes match, consider it the same device
            if total_checks > 0 and (match_score / total_checks) >= 0.75:
                is_match = True
                break
        
        if not is_match:
            risk_score = 60 * RiskConfig.WEIGHTS['device_fingerprint']
            metrics['new_device'] = True
        else:
            metrics['known_device'] = True
        
    except Exception as e:
        logger.error(f"Device analysis error: {e}")
    
    return round(risk_score, 2), metrics


# ========================================
# MAIN RISK ORCHESTRATOR
# ========================================

def analyze_risk(
    telemetry: Dict[str, Any],
    profile: Dict[str, Any]
) -> Tuple[int, str, Dict[str, Any]]:
    """
    Main risk analysis orchestrator
    
    Combines multiple detection methods:
    1. Bot detection (entropy analysis)
    2. Typing dynamics (Z-score analysis)
    3. Mouse behavior (pattern recognition)
    4. Geo-velocity (impossible travel)
    5. Device fingerprinting (consistency check)
    
    Args:
        telemetry: Real-time behavioral data from client
        profile: User's historical baseline profile
    
    Returns:
        Tuple of (risk_score, reason, detailed_metrics)
    """
    total_risk = 0.0
    reasons = []
    metrics = {
        'timestamp': datetime.utcnow().isoformat(),
        'analysis_version': '2.0'
    }
    
    # 1. ENVIRONMENT CHECK
    env_anomalies = detect_environment_anomalies(telemetry)
    if env_anomalies:
        metrics['environment_anomalies'] = env_anomalies
        reasons.append(f"Environment: {', '.join(env_anomalies)}")
        total_risk += 30
    
    # 2. BOT DETECTION (Mouse Entropy)
    mouse_path = telemetry.get('mouse_path', [])
    entropy, mouse_anomalies = detect_bot_movement(mouse_path)
    metrics['mouse_entropy'] = entropy
    
    if entropy < RiskConfig.ENTROPY_THRESHOLD_LOW:
        total_risk += 85 * RiskConfig.WEIGHTS['mouse_dynamics']
        reasons.append(f"Bot detected: Low movement entropy ({entropy})")
        metrics['bot_detected'] = True
    
    if mouse_anomalies:
        metrics['mouse_anomalies'] = mouse_anomalies
    
    # 3. TYPING DYNAMICS ANALYSIS
    typing_risk, typing_metrics = analyze_typing_dynamics(telemetry, profile)
    total_risk += typing_risk
    metrics['typing_dynamics'] = typing_metrics
    
    if typing_risk > 20:
        reasons.append("Anomalous typing pattern detected")
    
    # 4. GEO-VELOCITY CHECK
    geo_risk, geo_metrics = analyze_geo_anomalies(telemetry, profile)
    total_risk += geo_risk
    metrics['geo_analysis'] = geo_metrics
    
    if geo_risk > 50:
        reasons.append("Impossible travel detected")
    
    # 5. DEVICE FINGERPRINT
    device_risk, device_metrics = analyze_device_consistency(telemetry, profile)
    total_risk += device_risk
    metrics['device_analysis'] = device_metrics
    
    if device_risk > 30:
        reasons.append("Unrecognized device")
    
    # 6. CHECK IF USER IS ALREADY LOCKED
    if profile.get('is_locked'):
        total_risk = 100
        reasons = [profile.get('locked_reason', 'Account locked')]
    
    # Base risk floor
    total_risk = max(total_risk, 10)
    
    # Cap at 100
    final_score = min(int(total_risk), 100)
    
    # Compile reason string
    if not reasons:
        reason_str = "Normal behavior"
    else:
        reason_str = "; ".join(reasons[:3])  # Top 3 reasons
    
    metrics['risk_score'] = final_score
    metrics['risk_factors'] = reasons
    
    logger.info(f"Risk Analysis: Score={final_score}, Reasons={reason_str}")
    
    return final_score, reason_str, metrics


# ========================================
# MACHINE LEARNING MODEL (Optional Enhancement)
# ========================================

class MLRiskPredictor:
    """
    Advanced ML-based risk prediction using Isolation Forest
    Can be trained on historical data for improved accuracy
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def extract_features(self, telemetry: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from telemetry data"""
        features = []
        
        # Flight time statistics
        flight_vec = telemetry.get('flight_vec', [])
        if flight_vec:
            features.extend([
                np.mean(flight_vec),
                np.std(flight_vec),
                np.median(flight_vec)
            ])
        else:
            features.extend([0, 0, 0])
        
        # Dwell time statistics
        dwell_vec = telemetry.get('dwell_vec', [])
        if dwell_vec:
            features.extend([
                np.mean(dwell_vec),
                np.std(dwell_vec)
            ])
        else:
            features.extend([0, 0])
        
        # Mouse entropy
        mouse_path = telemetry.get('mouse_path', [])
        entropy, _ = detect_bot_movement(mouse_path)
        features.append(entropy)
        
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict[str, Any]]):
        """Train the Isolation Forest model"""
        if len(training_data) < 10:
            logger.warning("Insufficient training data")
            return
        
        # Extract features from all samples
        features_list = [self.extract_features(data) for data in training_data]
        X = np.vstack(features_list)
        
        # Standardize features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=RiskConfig.ISOLATION_CONTAMINATION,
            n_estimators=RiskConfig.ISOLATION_N_ESTIMATORS,
            random_state=42
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        
        logger.info("ML model trained successfully")
    
    def predict_risk(self, telemetry: Dict[str, Any]) -> float:
        """Predict anomaly score using trained model"""
        if not self.is_trained or not self.model:
            return 0.0
        
        features = self.extract_features(telemetry)
        features_scaled = self.scaler.transform(features)
        
        # Get anomaly score (-1 = anomaly, 1 = normal)
        score = self.model.decision_function(features_scaled)[0]
        
        # Convert to risk score (0-100)
        # More negative = more anomalous = higher risk
        risk_score = max(0, min(100, (1 - score) * 50))
        
        return round(risk_score, 2)
    
    def save_model(self, path: str):
        """Save trained model to disk"""
        if self.is_trained:
            joblib.dump({
                'model': self.model,
                'scaler': self.scaler
            }, path)
            logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str):
        """Load trained model from disk"""
        try:
            data = joblib.load(path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.is_trained = True
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")


if __name__ == "__main__":
    # Test the risk analysis system
    print("Testing AuthGuard Risk Analysis Engine...")
    
    # Mock telemetry data
    test_telemetry = {
        'flight_vec': [120, 135, 110, 125, 130],
        'dwell_vec': [45, 50, 48, 52, 47],
        'mouse_path': [
            {'x': 100, 'y': 100, 't': 0},
            {'x': 150, 'y': 120, 't': 50},
            {'x': 200, 'y': 150, 't': 100}
        ],
        'bot_flags': [],
        'fingerprint': {
            'userAgent': 'Mozilla/5.0',
            'screenRes': '1920x1080',
            'cores': 8
        }
    }
    
    # Mock profile data
    test_profile = {
        'baseline_stats': {
            'flight_mean': 125,
            'flight_std': 15,
            'dwell_mean': 48,
            'dwell_std': 5
        },
        'is_locked': False
    }
    
    # Run analysis
    risk_score, reason, metrics = analyze_risk(test_telemetry, test_profile)
    
    print(f"\n=== ANALYSIS RESULTS ===")
    print(f"Risk Score: {risk_score}/100")
    print(f"Reason: {reason}")
    print(f"Metrics: {metrics}")