from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple
from collections import defaultdict

# When authenticator (TOTP) is enabled, require a successful OTP at least this often.
OTP_REVERIFY_DAYS = 7

user_last_ip: Dict[str, str] = {}

failed_attempts: Dict[str, list] = defaultdict(list)

def analyze_risk(email: str, client_ip: str) -> Dict[str, any]:
    risk_factors = []
    is_risky = False

    if email == "michaokun@gmail.com":
        return {
            "is_risky": True,
            "risk_factors": ["Testing mode - forced risky"]
        }

    if email in user_last_ip:
        if user_last_ip[email] != client_ip:
            risk_factors.append("IP address changed")
            is_risky = True
    else:
        user_last_ip[email] = client_ip

    now = datetime.now()
    one_hour_ago = now - timedelta(hours=1)

    recent_failures = [
        attempt_time
        for attempt_time in failed_attempts.get(email, [])
        if attempt_time > one_hour_ago
    ]

    if len(recent_failures) >= 3:
        risk_factors.append("Multiple failed login attempts")
        is_risky = True
    
    return {
        "is_risky": is_risky,
        "risk_factors": risk_factors,
    }

def record_failed_attempt(email: str):
    failed_attempts[email].append(datetime.now())

    one_hour_ago = datetime.now() - timedelta(hours=1)
    failed_attempts[email] = [
        attempt for attempt in failed_attempts[email]
        if attempt > one_hour_ago
    ]

def record_successful_login(email: str, client_ip: str):
    user_last_ip[email] = client_ip
    if email in failed_attempts:
        failed_attempts[email].clear()


def otp_periodic_reverify_is_required(
    otp_enabled: bool,
    last_totp_verified_at: Optional[datetime],
    now: datetime,
) -> Tuple[bool, str]:
    """
    Extra risk factor for OTP users: require TOTP again after OTP_REVERIFY_DAYS
    since the last successful /user/verify-otp (or if never verified).
    """
    if not otp_enabled:
        return False, ""
    if last_totp_verified_at is None:
        return True, "Authenticator verification required (first time or 7-day policy)"
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if last_totp_verified_at.tzinfo is None:
        last_totp_verified_at = last_totp_verified_at.replace(tzinfo=timezone.utc)
    if now - last_totp_verified_at > timedelta(days=OTP_REVERIFY_DAYS):
        return True, "Authenticator re-verification required (7 days since last OTP)"
    return False, ""