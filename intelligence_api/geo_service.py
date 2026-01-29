"""
AuthGuard Enterprise - Geo-Location Service
IP-based geolocation and impossible travel detection
"""

import os
import logging
import requests
from typing import Optional, Dict, Any
from datetime import datetime
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_db import get_cache

logger = logging.getLogger(__name__)


class GeoLocationService:
    """
    Geolocation service for IP tracking and velocity analysis
    Supports multiple providers with fallback
    """
    
    def __init__(self):
        self.cache = get_cache()
        self.api_key = os.getenv('GEO_API_KEY')
        self.cache_ttl = 86400  # Cache for 24 hours
        
        # API endpoints
        self.providers = {
            'ipapi': 'http://ip-api.com/json/{}',
            'ipgeolocation': 'https://api.ipgeolocation.io/ipgeo?apiKey={}&ip={}',
            'ipinfo': 'https://ipinfo.io/{}/json'
        }
    
    def get_location_from_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Get geographic location from IP address
        
        Args:
            ip_address: IP address to lookup
        
        Returns:
            Dict with location data or None if failed
            {
                'ip': '1.2.3.4',
                'lat': 40.7128,
                'lon': -74.0060,
                'city': 'New York',
                'region': 'New York',
                'country': 'US',
                'timezone': 'America/New_York'
            }
        """
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            logger.debug(f"Skipping private IP: {ip_address}")
            return None
        
        # Check cache first
        cache_key = f"geo:{ip_address}"
        cached_data = self.cache.get(cache_key)
        
        if cached_data:
            logger.debug(f"Geo cache HIT: {ip_address}")
            return cached_data
        
        # Try each provider until one succeeds
        for provider, url_template in self.providers.items():
            try:
                logger.debug(f"Trying geo provider: {provider}")
                location_data = self._fetch_from_provider(
                    provider, 
                    url_template, 
                    ip_address
                )
                
                if location_data:
                    # Cache the result
                    self.cache.set(cache_key, location_data, ttl=self.cache_ttl)
                    logger.info(f"Geo lookup success: {ip_address} -> {location_data.get('city')}")
                    return location_data
                    
            except Exception as e:
                logger.warning(f"Geo provider {provider} failed: {e}")
                continue
        
        logger.warning(f"All geo providers failed for {ip_address}")
        return None
    
    def _fetch_from_provider(
        self, 
        provider: str, 
        url_template: str, 
        ip_address: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch location data from specific provider"""
        
        try:
            # Build URL based on provider
            if provider == 'ipapi':
                url = url_template.format(ip_address)
            elif provider == 'ipgeolocation' and self.api_key:
                url = url_template.format(self.api_key, ip_address)
            elif provider == 'ipinfo':
                url = url_template.format(ip_address)
            else:
                return None
            
            # Make request
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            # Normalize data format
            return self._normalize_response(provider, data, ip_address)
            
        except requests.RequestException as e:
            logger.error(f"Geo API request error: {e}")
            return None
    
    def _normalize_response(
        self, 
        provider: str, 
        data: Dict[str, Any], 
        ip_address: str
    ) -> Dict[str, Any]:
        """Normalize different provider responses to common format"""
        
        if provider == 'ipapi':
            return {
                'ip': ip_address,
                'lat': data.get('lat'),
                'lon': data.get('lon'),
                'city': data.get('city'),
                'region': data.get('regionName'),
                'country': data.get('countryCode'),
                'timezone': data.get('timezone')
            }
        
        elif provider == 'ipgeolocation':
            return {
                'ip': ip_address,
                'lat': float(data.get('latitude', 0)),
                'lon': float(data.get('longitude', 0)),
                'city': data.get('city'),
                'region': data.get('state_prov'),
                'country': data.get('country_code2'),
                'timezone': data.get('time_zone', {}).get('name')
            }
        
        elif provider == 'ipinfo':
            loc = data.get('loc', '0,0').split(',')
            return {
                'ip': ip_address,
                'lat': float(loc[0]) if len(loc) > 0 else 0,
                'lon': float(loc[1]) if len(loc) > 1 else 0,
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country'),
                'timezone': data.get('timezone')
            }
        
        return {}
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        if not ip:
            return True
        
        private_ranges = [
            '127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.', 'localhost'
        ]
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def calculate_distance(
        self, 
        loc1: Dict[str, float], 
        loc2: Dict[str, float]
    ) -> float:
        """
        Calculate distance between two coordinates using Haversine formula
        
        Args:
            loc1: {'lat': X, 'lon': Y}
            loc2: {'lat': X, 'lon': Y}
        
        Returns:
            Distance in kilometers
        """
        from math import radians, sin, cos, sqrt, atan2
        
        try:
            lat1, lon1 = loc1['lat'], loc1['lon']
            lat2, lon2 = loc2['lat'], loc2['lon']
            
            # Earth's radius in km
            R = 6371.0
            
            # Convert to radians
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            
            # Haversine formula
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * atan2(sqrt(a), sqrt(1-a))
            
            distance = R * c
            return round(distance, 2)
            
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"Distance calculation error: {e}")
            return 0.0
    
    def detect_vpn(self, ip_address: str) -> bool:
        """
        Detect if IP is from a known VPN/proxy service
        (Requires premium API - placeholder for now)
        
        Args:
            ip_address: IP to check
        
        Returns:
            True if VPN detected
        """
        # This would integrate with services like:
        # - IPQualityScore
        # - IP2Proxy
        # - IPQS
        
        # Placeholder implementation
        logger.debug(f"VPN detection not implemented for {ip_address}")
        return False
    
    def get_country_risk_score(self, country_code: str) -> int:
        """
        Get risk score for country (0-100)
        Based on fraud statistics
        
        Args:
            country_code: ISO 2-letter country code
        
        Returns:
            Risk score (0 = low, 100 = high)
        """
        # High-risk countries (based on fraud statistics)
        high_risk = ['NG', 'RU', 'CN', 'UA', 'VN', 'PH']
        medium_risk = ['IN', 'PK', 'BD', 'ID', 'BR']
        
        if country_code in high_risk:
            return 75
        elif country_code in medium_risk:
            return 50
        else:
            return 25
    
    def analyze_travel_pattern(
        self,
        locations: list,
        timestamps: list
    ) -> Dict[str, Any]:
        """
        Analyze a series of locations/timestamps for impossible travel
        
        Args:
            locations: List of {'lat': X, 'lon': Y} dicts
            timestamps: List of datetime objects
        
        Returns:
            Analysis results
        """
        if len(locations) < 2 or len(timestamps) < 2:
            return {'valid': True, 'issues': []}
        
        issues = []
        max_velocity = 0
        
        for i in range(1, len(locations)):
            loc1, loc2 = locations[i-1], locations[i]
            time1, time2 = timestamps[i-1], timestamps[i]
            
            # Calculate distance
            distance = self.calculate_distance(loc1, loc2)
            
            # Calculate time difference in hours
            time_diff = (time2 - time1).total_seconds() / 3600
            
            if time_diff > 0:
                # Calculate velocity (km/h)
                velocity = distance / time_diff
                max_velocity = max(max_velocity, velocity)
                
                # Flag impossible travel (>1000 km/h)
                if velocity > 1000:
                    issues.append({
                        'type': 'impossible_travel',
                        'velocity': round(velocity, 2),
                        'distance': distance,
                        'time_hours': round(time_diff, 2)
                    })
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'max_velocity_kmh': round(max_velocity, 2)
        }


# Singleton instance
_geo_service_instance = None

def get_geo_service() -> GeoLocationService:
    """Get geo service singleton instance"""
    global _geo_service_instance
    if not _geo_service_instance:
        _geo_service_instance = GeoLocationService()
    return _geo_service_instance


if __name__ == "__main__":
    # Test geo service
    print("Testing Geo-Location Service...")
    
    service = GeoLocationService()
    
    # Test IP lookup
    test_ip = "8.8.8.8"  # Google DNS
    print(f"\nLooking up {test_ip}...")
    location = service.get_location_from_ip(test_ip)
    print(f"Result: {location}")
    
    # Test distance calculation
    if location:
        ny_location = {'lat': 40.7128, 'lon': -74.0060}
        distance = service.calculate_distance(location, ny_location)
        print(f"\nDistance to NYC: {distance} km")