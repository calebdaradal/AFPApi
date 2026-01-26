from datetime import datetime, timedelta
from typing import Dict, Optional
from collections import defaultdict

user_last_ip: Dict[str, str] = {}

failed_attempts: Dict[str, list] = defaultdict(list)

def analyze_risk(email: str, client_ip: str) -> Dict[str, any]:
    risk_factors = []
    is_risky = False

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