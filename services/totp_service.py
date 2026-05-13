import pyotp
from typing import Optional

from services.mongo_client import get_users_collection

# TOTP secrets are stored on each user document as `totp_secret` (persisted; survives API restarts).


def totp_provisioning_uri(
    secret: str, email: str, issuer: str = "AFP App"
) -> str:
    """Build an otpauth:// URI for QR / manual setup (does not touch the database)."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def get_totp_secret(email: str) -> Optional[str]:
    """Read stored TOTP secret for a registered user."""
    users = get_users_collection()
    user = users.find_one({"email": email})
    if not user:
        return None
    secret = user.get("totp_secret")
    if isinstance(secret, str):
        s = secret.strip()
        return s if s else None
    return None


def generate_totp_secret(email: str) -> str:
    """Create a new secret and save it on the user document (replaces any existing secret)."""
    users = get_users_collection()
    if users.find_one({"email": email}) is None:
        raise ValueError("No user registered with this email")
    secret = pyotp.random_base32()
    users.update_one({"email": email}, {"$set": {"totp_secret": secret}})
    return secret


def get_or_create_totp_secret(email: str) -> str:
    """Return the user's existing secret, or create and persist one if missing."""
    existing = get_totp_secret(email)
    if existing:
        return existing
    return generate_totp_secret(email)


def verify_totp(email: str, otp_code: str) -> bool:
    """Check the 6-digit code against the user's stored secret."""
    secret = get_totp_secret(email)
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    code = (otp_code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    # valid_window=2 allows ±2 steps (~60s) for phone/server clock skew
    return totp.verify(code, valid_window=2)


def get_totp_uri(email: str, issuer: str = "AFP App") -> str:
    """URI for enrolling Authenticator; creates a secret only if the user has none yet."""
    secret = get_or_create_totp_secret(email)
    return totp_provisioning_uri(secret, email, issuer=issuer)
