"""
User validation against MongoDB. Passwords stored as bcrypt hashes.
Uses bcrypt package directly (passlib incompatible with newer bcrypt).
"""
import bcrypt
from services.mongo_client import get_users_collection

# Bcrypt only hashes first 72 bytes
_MAX_PASSWORD_BYTES = 72


def _to_bytes(s: str) -> bytes:
    """Encode password to bytes and truncate to bcrypt limit."""
    b = s.encode("utf-8")
    return b[:_MAX_PASSWORD_BYTES] if len(b) > _MAX_PASSWORD_BYTES else b


def hash_password(plain_password: str) -> str:
    """Hash a plain password for storing in DB."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(_to_bytes(plain_password), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check plain password against stored hash."""
    return bcrypt.checkpw(
        _to_bytes(plain_password),
        hashed_password.encode("utf-8"),
    )


def validate_user(email: str, password: str) -> bool:
    """
    Check credentials against MongoDB users collection.
    Returns True only if user exists and password matches.
    """
    users = get_users_collection()
    user = users.find_one({"email": email})
    if not user:
        return False
    if not verify_password(password, user["password_hash"]):
        return False
    return True
