from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Limiter with in-memory storage for the prototype
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)