import pyotp
import secrets
from typing import Optional

user_totp_secrets: dict[str, str] = {}

def generate_totp_secret(email: str) -> str:
    secret = pyotp.random_base32()
    user_totp_secrets[email] = secret
    return secret

def get_totp_secret(email: str) -> Optional[str]:
    return user_totp_secrets.get(email)

def verify_totp(email: str, otp_code: str) -> bool:
    secret = get_totp_secret(email)
    if not secret:
        return False
    
    totp = pyotp.TOTP(secret)

    return totp.verify(otp_code, valid_window=1)

def get_totp_uri(email: str, issuer: str = "AFP App") -> str:

    secret = get_totp_secret(email)
    if not secret:
        secret = generate_totp_secret(email)

    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=issuer
    )