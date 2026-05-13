import re
from typing import Optional

import pyotp

from services.mongo_client import get_users_collection

# TOTP secrets are stored on each user document as `totp_secret` (persisted; survives API restarts).


def _normalize_secret(raw) -> Optional[str]:
    """Turn Mongo-stored secret into a base32 string Google Authenticator expects."""
    if raw is None:
        return None
    if isinstance(raw, bytes):
        s = raw.decode("utf-8", errors="replace").strip()
        return s if s else None
    if isinstance(raw, str):
        s = raw.strip().replace(" ", "")
        return s if s else None
    s = str(raw).strip()
    return s if s else None


def canonical_email_for_user(raw_email: str) -> Optional[str]:
    """
    Resolve the exact `email` field on the user document (case-insensitive match).
    Login/verify/setup may use different casing than MongoDB.
    """
    raw = (raw_email or "").strip()
    if not raw:
        return None
    users = get_users_collection()
    user = users.find_one({"email": raw})
    if user:
        em = user.get("email")
        return em.strip() if isinstance(em, str) else None
    user = users.find_one(
        {"email": {"$regex": f"^{re.escape(raw)}$", "$options": "i"}}
    )
    if not user:
        return None
    em = user.get("email")
    return em.strip() if isinstance(em, str) else None


def totp_provisioning_uri(
    secret: str, email: str, issuer: str = "AFP App"
) -> str:
    """Build an otpauth:// URI for QR / manual setup (does not touch the database)."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def get_totp_secret(raw_email: str) -> Optional[str]:
    """Read stored TOTP secret for a registered user."""
    canonical = canonical_email_for_user(raw_email)
    if not canonical:
        return None
    users = get_users_collection()
    user = users.find_one({"email": canonical})
    if not user:
        return None
    return _normalize_secret(user.get("totp_secret"))


def generate_totp_secret(raw_email: str) -> str:
    """Create a new secret and save it (replaces any existing secret)."""
    canonical = canonical_email_for_user(raw_email)
    if not canonical:
        raise ValueError("No user registered with this email")
    users = get_users_collection()
    secret = pyotp.random_base32()
    users.update_one({"email": canonical}, {"$set": {"totp_secret": secret}})
    return secret


def get_or_create_totp_secret(raw_email: str) -> str:
    """Return existing secret or create and persist one; uses canonical email on the user doc."""
    existing = get_totp_secret(raw_email)
    if existing:
        return existing
    return generate_totp_secret(raw_email)


def verify_totp(raw_email: str, otp_code: str) -> bool:
    """Check the 6-digit code against the user's stored secret."""
    secret = get_totp_secret(raw_email)
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    code = (otp_code or "").strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return False
    # valid_window: extra intervals for phone vs server clock skew (30s per step)
    return totp.verify(code, valid_window=4)


def get_totp_uri(raw_email: str, issuer: str = "AFP App") -> str:
    """URI for enrolling Authenticator; creates a secret only if the user has none yet."""
    secret = get_or_create_totp_secret(raw_email)
    canonical = canonical_email_for_user(raw_email) or raw_email.strip()
    return totp_provisioning_uri(secret, canonical, issuer=issuer)
