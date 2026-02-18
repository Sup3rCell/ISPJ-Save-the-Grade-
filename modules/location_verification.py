"""
Location Verification Module with Geo-IP Lookup and Impossible Travel Detection
Uses ipinfo.io API for geolocation data
"""

import requests
import json
from datetime import datetime, timedelta
from models import db, AccessLog, User
from config import Config
import math

class LocationVerifier:
    """
    Handles geo-IP verification and impossible travel detection
    """
    
    def __init__(self):
        self.ipinfo_token = Config.IPINFO_TOKEN
        self.ipinfo_url = "https://ipinfo.io"
        self.earth_radius_km = 6371  # For distance calculation
        
    def get_location_from_ip(self, ip_address):
        """
        Get geolocation data from ipinfo.io API
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            dict: Location data {city, region, country, lat, lon, org}
        """
        if not self.ipinfo_token:
            print("⚠️ Warning: IPINFO_TOKEN not configured")
            return None
            
        try:
            url = f"{self.ipinfo_url}/{ip_address}?token={self.ipinfo_token}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                location_info = {
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'country': data.get('country', 'XX'),
                    'latitude': float(data.get('loc', '0,0').split(',')[0]),
                    'longitude': float(data.get('loc', '0,0').split(',')[1]),
                    'org': data.get('org', 'Unknown'),
                    'timezone': data.get('timezone', 'Unknown'),
                    'isp': data.get('isp', 'Unknown')
                }
                return location_info
            else:
                print(f"❌ ipinfo.io error: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Request error: {e}")
            return None
    
    def calculate_distance(self, lat1, lon1, lat2, lon2):
        """
        Calculate great circle distance between two points (Haversine formula)
        
        Args:
            lat1, lon1: First point coordinates
            lat2, lon2: Second point coordinates
            
        Returns:
            float: Distance in kilometers
        """
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return self.earth_radius_km * c
    
    def detect_impossible_travel(self, user_id, current_ip, current_location):
        """
        Detect if user has traveled an impossible distance in the given time
        
        Args:
            user_id: User ID
            current_ip: Current IP address
            current_location: Current location dict with lat/lon
            
        Returns:
            dict: {is_impossible: bool, risk_factor: str, details: dict}
        """
        if not current_location:
            return {
                'is_impossible': False,
                'risk_factor': None,
                'details': 'No location data available'
            }
        
        # Get the last access from this user in the last 24 hours
        last_log = AccessLog.query.filter_by(user_id=user_id).order_by(
            AccessLog.timestamp.desc()
        ).first()
        
        if not last_log:
            # First access from this user
            return {
                'is_impossible': False,
                'risk_factor': None,
                'details': 'First login detected'
            }
        
        # Check if last location data exists
        if not last_log.location:
            return {
                'is_impossible': False,
                'risk_factor': None,
                'details': 'Previous location unavailable'
            }
        
        try:
            last_location = json.loads(last_log.location)
        except (json.JSONDecodeError, TypeError):
            return {
                'is_impossible': False,
                'risk_factor': None,
                'details': 'Cannot parse previous location'
            }
        
        # Calculate time difference in hours
        time_diff = (datetime.utcnow() - last_log.timestamp).total_seconds() / 3600
        
        if time_diff < 0.1:  # Less than 6 minutes
            return {
                'is_impossible': False,
                'risk_factor': None,
                'details': 'Too recent to detect travel'
            }
        
        # Calculate distance
        distance_km = self.calculate_distance(
            last_location.get('latitude', 0),
            last_location.get('longitude', 0),
            current_location['latitude'],
            current_location['longitude']
        )
        
        # Maximum reasonable speed: 900 km/h (commercial flight speed)
        max_speed_kmh = 900
        max_distance = max_speed_kmh * time_diff
        
        is_impossible = distance_km > max_distance
        
        result = {
            'is_impossible': is_impossible,
            'distance_km': round(distance_km, 2),
            'time_hours': round(time_diff, 2),
            'max_distance_km': round(max_distance, 2),
            'required_speed_kmh': round(distance_km / time_diff, 2) if time_diff > 0 else 0,
            'previous_location': f"{last_location.get('city')}, {last_location.get('country')}",
            'current_location': f"{current_location['city']}, {current_location['country']}"
        }
        
        if is_impossible:
            result['risk_factor'] = 'IMPOSSIBLE_TRAVEL'
            result['severity'] = 'HIGH'
        else:
            result['risk_factor'] = None
            result['severity'] = 'LOW'
        
        return result
    
    def update_user_location(self, user_id, ip_address):
        """
        Update user's current location in their session/profile
        
        Args:
            user_id: User ID
            ip_address: Current IP address
            
        Returns:
            dict: Location info with risk assessment
        """
        location_info = self.get_location_from_ip(ip_address)
        
        if location_info:
            # Detect impossible travel
            travel_check = self.detect_impossible_travel(user_id, ip_address, location_info)
            
            return {
                'success': True,
                'location': location_info,
                'travel_check': travel_check
            }
        
        return {
            'success': False,
            'error': 'Could not retrieve location data'
        }


def verify_location_on_login(user_id, ip_address):
    """
    Helper function to verify location during login
    Returns risk score based on location anomalies
    """
    verifier = LocationVerifier()
    result = verifier.update_user_location(user_id, ip_address)
    
    risk_score = 0
    risk_factors = []
    
    if result['success']:
        location_data = result['location']
        travel_check = result['travel_check']
        
        # Store location in AccessLog format
        location_json = json.dumps({
            'city': location_data.get('city'),
            'region': location_data.get('region'),
            'country': location_data.get('country'),
            'latitude': location_data.get('latitude'),
            'longitude': location_data.get('longitude'),
            'org': location_data.get('org'),
            'timezone': location_data.get('timezone'),
            'isp': location_data.get('isp')
        })
        
        # Check for impossible travel
        if travel_check.get('is_impossible'):
            risk_score += 40
            risk_factors.append('Impossible travel detected')
        
        return {
            'location_json': location_json,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'travel_check': travel_check
        }
    
    return {
        'location_json': None,
        'risk_score': 10,
        'risk_factors': ['Could not verify location'],
        'travel_check': None
    }
