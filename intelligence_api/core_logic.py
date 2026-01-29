import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# --- INDUSTRY STANDARD CONFIG ---
# Weights determine how important each factor is
WEIGHTS = {
    'flight_time': 0.4,   # Typing rhythm is very unique
    'mouse_entropy': 0.3, # Bot detection
    'dwell_time': 0.2,    # Key press duration
    'scroll_speed': 0.1
}

def calculate_z_score(current_val, baseline_mean, baseline_std):
    """
    Returns how many standard deviations away the current action is.
    Z > 3 is highly suspicious (99.7% confidence).
    """
    if baseline_std == 0: return 0 # Avoid division by zero
    return abs((current_val - baseline_mean) / baseline_std)

def detect_bot_movement(mouse_path):
    """
    Analyzes angular entropy. 
    Low Entropy (< 0.5) = Straight lines = BOT.
    High Entropy (> 2.0) = Chaotic = HUMAN.
    """
    if not mouse_path or len(mouse_path) < 3: return 0.5
    
    angles = []
    for i in range(1, len(mouse_path)-1):
        p1, p2, p3 = mouse_path[i-1], mouse_path[i], mouse_path[i+1]
        # Calculate angle between 3 points
        # (Math omitted for brevity, assumes standard arctan2 logic)
        angle = np.arctan2(p3['y'] - p2['y'], p3['x'] - p2['x']) - \
                np.arctan2(p2['y'] - p1['y'], p2['x'] - p1['x'])
        angles.append(angle)
    
    # Calculate Shannon Entropy of the angle distribution
    hist, _ = np.histogram(angles, bins=10, density=True)
    entropy = -np.sum(hist * np.log(hist + 1e-9))
    
    return entropy

def analyze_risk(telemetry, profile):
    """
    Main Orchestrator:
    1. Checks for Bot Patterns (Entropy)
    2. Checks for Behavioral Deviation (Z-Score)
    3. Returns composite Risk Score (0-100)
    """
    risk_accumulated = 0
    stats = profile.get('baseline_stats', {})
    
    # 1. BOT CHECK (Mouse Entropy)
    current_entropy = detect_bot_movement(telemetry.get('mouse_path', []))
    if current_entropy < 0.8: # Threshold for robotic movement
        return 95, "Bot detected: Low movement entropy"

    # 2. TYPING RHYTHM (Flight Time)
    if 'flight_vec' in telemetry and 'flight_mean' in stats:
        current_flight = np.mean(telemetry['flight_vec'])
        z_flight = calculate_z_score(current_flight, stats['flight_mean'], stats.get('flight_std', 10))
        
        # Sigmoid scaling: Z=3 -> Risk increases sharply
        if z_flight > 2.5: 
            risk_accumulated += 40 * WEIGHTS['flight_time']
            
    # 3. DWELL TIME
    if 'dwell_vec' in telemetry and 'dwell_mean' in stats:
        current_dwell = np.mean(telemetry['dwell_vec'])
        z_dwell = calculate_z_score(current_dwell, stats['dwell_mean'], stats.get('dwell_std', 5))
        if z_dwell > 3:
            risk_accumulated += 30 * WEIGHTS['dwell_time']

    # Normalize to 0-100
    final_score = min(100, int(risk_accumulated + 10)) # Base risk is 10
    
    return final_score, "Behavioral deviation detected"