import jwt
from datetime import datetime, timedelta
from core.config import AppSettings

settings = AppSettings()

# Secret key for JWT (use environment variable in production)
JWT_SECRET_KEY = "your-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

def create_jwt_token(email: str) -> str:
    """
    Create a JWT token for authenticated user
    Returns the encoded JWT token string
    """
    # Set expiration time
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    
    # Create payload
    payload = {
        "email": email,
        "exp": expiration,
        "iat": datetime.utcnow()
    }
    
    # Encode and return token
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def verify_jwt_token(token: str) -> dict:
    """
    Verify and decode a JWT token
    Returns the payload if valid, raises exception if invalid
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")