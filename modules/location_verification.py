import math
from models import AccessLog
from datetime import datetime

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def check_impossible_travel(user_id, new_lat, new_lon, new_time):
    print("DEBUG: check_impossible_travel()", user_id, new_lat, new_lon, new_time)

    last = (AccessLog.query
            .filter(
                AccessLog.user_id == user_id,
                AccessLog.latitude.isnot(None),
                AccessLog.longitude.isnot(None),
                AccessLog.timestamp < new_time
            )
            .order_by(AccessLog.timestamp.desc())
            .first())

    print("DEBUG: last row =", last.id if last else None, last.timestamp if last else None)

    if not last:
        return None, None, False

    delta_hours = (new_time - last.timestamp).total_seconds() / 3600.0
    if delta_hours <= 0:
        return None, None, False

    distance_km = haversine_km(last.latitude, last.longitude, new_lat, new_lon)
    speed_kmh = distance_km / delta_hours
    print("DEBUG: distance_km =", distance_km, "speed_kmh =", speed_kmh)

    impossible = speed_kmh > 50
    return distance_km, speed_kmh, impossible


