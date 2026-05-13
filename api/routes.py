from fastapi import APIRouter, HTTPException, Request, Header
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta, timezone
import base64
import binascii
import hashlib
from urllib.parse import quote
from bson import ObjectId
from bson.errors import InvalidId
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from schemas.user_schema import (
    LoginInput,
    RegisterInput,
    UserResponse,
    OTPVerificationInput,
    UserProfileResponse,
    UserProfileUpdateInput,
    CustomerCreateInput,
    RecordCreateInput,
    OtpSetupPromptInput,
)
from services.user_service import validate_user, hash_password
from services.mongo_client import get_users_collection, get_customers_collection, get_records_collection
from services.risk_engine import (
    analyze_risk,
    record_failed_attempt,
    record_successful_login,
    otp_periodic_reverify_is_required,
)
from services.totp_service import (
    verify_totp,
    get_or_create_totp_secret,
    canonical_email_for_user,
    get_totp_secret,
    totp_provisioning_uri,
)
from services.jwt_service import create_jwt_token, verify_jwt_token
from core.config import AppSettings
from core.rate_limit import limiter
from loguru import logger

router = APIRouter()
settings = AppSettings()

_OTP_NUDGE_DAYS = 30


def _maybe_refresh_periodic_otp_prompt(users, email_canon: str) -> None:
    """If OTP is off and user dismissed setup, re-prompt after [_OTP_NUDGE_DAYS]."""
    user = users.find_one({"email": email_canon})
    if not user or user.get("otp_enabled"):
        return
    if user.get("otp_setup_prompt_pending"):
        return
    last = user.get("otp_last_nudge_at")
    now = datetime.now(timezone.utc)
    due = False
    if not last:
        due = True
    else:
        try:
            s = str(last).replace("Z", "+00:00")
            parsed = datetime.fromisoformat(s)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if now - parsed > timedelta(days=_OTP_NUDGE_DAYS):
                due = True
        except Exception:
            due = True
    if due:
        users.update_one({"email": email_canon}, {"$set": {"otp_setup_prompt_pending": True}})


def _show_otp_setup_prompt(user: dict) -> bool:
    if user.get("otp_enabled"):
        return False
    return bool(user.get("otp_setup_prompt_pending"))


def _to_json_safe(value):
    """
    Recursively convert Mongo/BSON values (like ObjectId) into JSON-safe values.
    """
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, dict):
        return {k: _to_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_json_safe(item) for item in value]
    return value


def _decrypt_qr_customer_id(qr_payload: str) -> str:
    """
    Decrypt QR payload format "<iv_b64>.<ciphertext_b64>" using AES-256-GCM.
    Key is derived from SHA-256(qr_encryption_key).
    """
    parts = qr_payload.split(".")
    if len(parts) != 2:
        raise ValueError("Invalid encrypted QR format")
    iv_b64, ciphertext_b64 = parts[0].strip(), parts[1].strip()
    if not iv_b64 or not ciphertext_b64:
        raise ValueError("Invalid encrypted QR format")
    try:
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
    except (binascii.Error, ValueError):
        raise ValueError("Invalid encrypted QR base64 data")
    if len(iv) != 12:
        raise ValueError("Invalid IV length for AES-GCM")
    key = hashlib.sha256(settings.qr_encryption_key.encode("utf-8")).digest()
    aesgcm = AESGCM(key)
    try:
        decrypted = aesgcm.decrypt(iv, ciphertext, None)
    except Exception:
        raise ValueError("Failed to decrypt QR payload")
    customer_id = decrypted.decode("utf-8").strip()
    if not customer_id:
        raise ValueError("Decrypted customer_id is empty")
    return customer_id


def _resolve_customer_object_id(scanned_qr_value: str) -> ObjectId:
    """
    Accept either a plain Mongo ObjectId string or an encrypted QR payload.
    """
    raw_value = scanned_qr_value.strip()
    if not raw_value:
        raise HTTPException(status_code=400, detail="customer_id is required")
    try:
        return ObjectId(raw_value)
    except InvalidId:
        pass
    try:
        decrypted_id = _decrypt_qr_customer_id(raw_value)
        return ObjectId(decrypted_id)
    except (ValueError, InvalidId):
        raise HTTPException(
            status_code=400,
            detail="Invalid customer_id. Expected plain Mongo ID or valid encrypted QR payload.",
        )


def _get_email_from_authorization(authorization: Optional[str]) -> str:
    """
    Extract and validate JWT from Authorization header.
    Expected format: "Bearer <token>".
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing JWT token")
    try:
        payload = verify_jwt_token(token)
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid JWT payload")
        return email
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


def _parse_last_totp_verified_at(raw) -> Optional[datetime]:
    """Parse Mongo `last_totp_verified_at` ISO string to timezone-aware UTC datetime."""
    if not raw:
        return None
    try:
        s = str(raw).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(s)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _auth_email_and_require_fresh_totp_if_enabled(
    authorization: Optional[str],
) -> Tuple[str, Dict[str, Any]]:
    """
    Validate JWT and load user. If OTP is on and last TOTP success is older than policy,
    reject so the client clears the session and re-logs in with OTP.
    """
    email = _get_email_from_authorization(authorization)
    users = get_users_collection()
    user = users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    now_utc = datetime.now(timezone.utc)
    last_dt = _parse_last_totp_verified_at(user.get("last_totp_verified_at"))
    reverify, _ = otp_periodic_reverify_is_required(
        bool(user.get("otp_enabled", False)),
        last_dt,
        now_utc,
    )
    if reverify:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "OTP_REVERIFY_REQUIRED",
                "message": "Authenticator must be re-verified at least every 7 days. Please log in again.",
            },
        )
    return email, user


@router.post("/user/register")
@limiter.limit(settings.rate_limit)
async def register_user(request: Request, payload: RegisterInput):
    """
    Register a new user. Email must be unique; password is stored hashed.
    """
    users = get_users_collection()
    existing = users.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = hash_password(payload.password)
    users.insert_one({
        "email": payload.email,
        "password_hash": password_hash,
        "first_name": payload.first_name,
        "last_name": payload.last_name,
        "phone_number": payload.phone_number,
        "is_active": True,
        "image": (payload.image or "").strip(),
        "otp_enabled": False,
        "otp_setup_prompt_pending": True,
    })
    return {"message": "User registered successfully"}


@router.post("/user/login", response_model=UserResponse)
@limiter.limit(settings.rate_limit)
async def login_user(request: Request, payload: LoginInput):
    """
    If OTP is disabled for the user: password-only login (JWT issued).
    If OTP enabled: use risk_engine plus 7-day TOTP re-verify — non-risky and fresh → JWT; else OTP required first.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not validate_user(payload.email, payload.password):
        record_failed_attempt(payload.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    users = get_users_collection()
    email_stripped = payload.email.strip()
    canon = canonical_email_for_user(email_stripped) or email_stripped
    user = users.find_one({"email": canon})
    if not user:
        raise HTTPException(status_code=500, detail="User record not found")

    _maybe_refresh_periodic_otp_prompt(users, canon)
    user = users.find_one({"email": canon}) or user
    show_prompt = _show_otp_setup_prompt(user)
    risk_analysis = analyze_risk(canon, client_ip)

    if not user.get("otp_enabled", False):
        record_successful_login(canon, client_ip)
        token = create_jwt_token(canon)
        return UserResponse(
            message="Login successful",
            status_code=200,
            token=token,
            requires_otp=False,
            risk_factors=risk_analysis["risk_factors"],
            show_otp_setup_prompt=show_prompt,
        )

    now_utc = datetime.now(timezone.utc)
    last_dt = _parse_last_totp_verified_at(user.get("last_totp_verified_at"))
    reverify_needed, reverify_msg = otp_periodic_reverify_is_required(
        True,
        last_dt,
        now_utc,
    )
    risk_factors = list(risk_analysis["risk_factors"])
    if reverify_needed and reverify_msg:
        risk_factors.append(reverify_msg)

    needs_otp = risk_analysis["is_risky"] or reverify_needed
    if not needs_otp:
        record_successful_login(canon, client_ip)
        token = create_jwt_token(canon)
        return UserResponse(
            message="Login successful",
            status_code=200,
            token=token,
            requires_otp=False,
            risk_factors=risk_factors,
            show_otp_setup_prompt=False,
        )

    get_or_create_totp_secret(canon)
    return UserResponse(
        message="OTP verification required",
        status_code=202,
        token=None,
        requires_otp=True,
        risk_factors=risk_factors,
        show_otp_setup_prompt=False,
    )

@router.post("/user/verify-otp", response_model=UserResponse)
@limiter.limit(settings.rate_limit)
async def verify_otp(request: Request, payload: OTPVerificationInput):
    """
    Verify OTP code and issue JWT token
    """
    # Match trimmed/cased email to Mongo user + totp_secret
    client_ip = request.client.host if request.client else "unknown"
    email_in = payload.email.strip()

    if not verify_totp(email_in, payload.otp_code):
        has_secret = get_totp_secret(email_in) is not None
        logger.warning("OTP verification failed (has_stored_totp_secret={})", has_secret)
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    canonical = canonical_email_for_user(email_in) or email_in
    users = get_users_collection()
    users.update_one(
        {"email": canonical},
        {"$set": {"last_totp_verified_at": datetime.now(timezone.utc).isoformat()}},
    )
    record_successful_login(canonical, client_ip)
    token = create_jwt_token(canonical)
    return UserResponse(
        message="OTP verified successfully",
        status_code=200,
        token=token,
        requires_otp=False,
        show_otp_setup_prompt=False,
    )


@router.post("/user/otp-setup-response")
@limiter.limit(settings.rate_limit)
async def otp_setup_prompt_response(
    request: Request,
    payload: OtpSetupPromptInput,
    authorization: Optional[str] = Header(default=None),
):
    """After login: user accepts or declines optional OTP enrollment (requires JWT)."""
    email, _ = _auth_email_and_require_fresh_totp_if_enabled(authorization)
    users = get_users_collection()
    now_iso = datetime.now(timezone.utc).isoformat()
    if payload.accepted:
        get_or_create_totp_secret(email)
        users.update_one(
            {"email": email},
            {"$set": {"otp_enabled": True, "otp_setup_prompt_pending": False}},
        )
        path = f"user/setup-totp/{quote(email, safe='')}"
        return {
            "message": "OTP enabled. Open the URL below in a browser to scan your QR code.",
            "setup_totp_path": path,
        }
    users.update_one(
        {"email": email},
        {"$set": {"otp_setup_prompt_pending": False, "otp_last_nudge_at": now_iso}},
    )
    return {"message": "Acknowledged", "setup_totp_path": None}


@router.get("/user/profile", response_model=UserProfileResponse)
@limiter.limit(settings.rate_limit)
async def get_user_profile(request: Request, authorization: Optional[str] = Header(default=None)):
    """
    Get authenticated user's profile from MongoDB.
    """
    _, user = _auth_email_and_require_fresh_totp_if_enabled(authorization)
    raw_img = user.get("image", "")
    profile_image = raw_img.strip() if isinstance(raw_img, str) else ""
    return UserProfileResponse(
        email=user.get("email", ""),
        first_name=user.get("first_name", ""),
        last_name=user.get("last_name", ""),
        phone_number=user.get("phone_number", ""),
        is_active=user.get("is_active", False),
        image=profile_image,
        otp_enabled=bool(user.get("otp_enabled", False)),
    )


@router.put("/user/profile")
@limiter.limit(settings.rate_limit)
async def update_user_profile(
    request: Request,
    payload: UserProfileUpdateInput,
    authorization: Optional[str] = Header(default=None),
):
    """
    Update authenticated user's profile fields.
    """
    email, user = _auth_email_and_require_fresh_totp_if_enabled(authorization)
    users = get_users_collection()
    set_doc = {
        "first_name": payload.first_name,
        "last_name": payload.last_name,
        "phone_number": payload.phone_number,
        "image": (payload.image or "").strip(),
    }
    if payload.otp_enabled is not None:
        set_doc["otp_enabled"] = payload.otp_enabled
        if payload.otp_enabled:
            get_or_create_totp_secret(email)
    users.update_one(
        {"email": email},
        {"$set": set_doc},
    )
    return {"message": "Profile updated successfully"}


@router.post("/customer/create")
@limiter.limit(settings.rate_limit)
async def create_customer(request: Request, payload: CustomerCreateInput):
    """
    Create a customer record (development/dummy data support).
    """
    customers = get_customers_collection()
    result = customers.insert_one(
        {
            "first_name": payload.first_name,
            "last_name": payload.last_name,
            "address": payload.address,
            "age": payload.age,
            "car_model": payload.car_model,
            "car_make": payload.car_make,
            "plate_number": payload.plate_number,
            "active": payload.active,
            "vehicle_color": payload.vehicle_color,
            "image": payload.image,
        }
    )
    return {
        "message": "Customer created successfully",
        "customer_id": str(result.inserted_id),
    }


@router.get("/customer/ids")
@limiter.limit(settings.rate_limit)
async def get_customer_ids(request: Request):
    """
    Return all customer document IDs from the customers collection.
    """
    customers = get_customers_collection()
    docs = customers.find({}, {"_id": 1})
    ids = [str(doc["_id"]) for doc in docs]
    return {
        "count": len(ids),
        "ids": ids,
    }


@router.post("/record/create")
@limiter.limit(settings.rate_limit)
async def create_record(
    request: Request,
    payload: RecordCreateInput,
    authorization: Optional[str] = Header(default=None),
):
    """
    Create an IN/OUT record from a scanned customer QR code.
    """
    _auth_email_and_require_fresh_totp_if_enabled(authorization)
    scan_type = payload.type.strip().upper()
    if scan_type not in {"IN", "OUT"}:
        raise HTTPException(status_code=400, detail='Invalid type. Use "IN" or "OUT".')

    customer_object_id = _resolve_customer_object_id(payload.customer_id)

    customers = get_customers_collection()
    customer = customers.find_one({"_id": customer_object_id})
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    now = datetime.now()
    record_data = {
        "customer_id": str(customer["_id"]),
        "first_name": customer.get("first_name", ""),
        "last_name": customer.get("last_name", ""),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "type": scan_type,
    }
    records = get_records_collection()
    result = records.insert_one(record_data)

    response_payload = {
        "message": "Record created successfully",
        "record_id": str(result.inserted_id),
        "record": record_data,
        "customer": {
            "id": str(customer["_id"]),
            "first_name": customer.get("first_name", ""),
            "last_name": customer.get("last_name", ""),
            "address": customer.get("address", ""),
            "age": customer.get("age", 0),
            "car_model": customer.get("car_model", ""),
            "car_make": customer.get("car_make", ""),
            "plate_number": customer.get("plate_number", ""),
            "active": customer.get("active", False),
            "vehicle_color": customer.get("vehicle_color", ""),
            "image": customer.get("image", ""),
            # Second image URL from MongoDB field imageId (or snake_case image_id)
            "image_id": customer.get("imageId") or customer.get("image_id", ""),
            # Third image: person photo from MongoDB imagePerson (or snake_case image_person)
            "image_person": customer.get("imagePerson") or customer.get("image_person", ""),
        },
    }
    return _to_json_safe(response_payload)


@router.get("/user/test-otp/{email}")
async def get_test_otp(email: str):
    """
    TESTING ONLY: Get current OTP code for a user
    Remove this in production!
    """
    from services.totp_service import get_totp_secret
    import pyotp
    
    secret = get_totp_secret(email)
    if not secret:
        return {"error": "No TOTP secret found. Login first to generate one."}
    
    totp = pyotp.TOTP(secret)
    current_otp = totp.now()
    
    return {
        "email": email,
        "current_otp": current_otp,
        "warning": "This endpoint is for testing only!"
    }

@router.get("/user/setup-totp/{email}")
async def setup_totp(email: str):
    """
    Return a QR / URI for Google Authenticator.
    Reuses the existing stored secret when present so reopening this URL does not invalidate the app.
    """
    import qrcode
    import io
    import base64

    email_in = email.strip()
    try:
        secret = get_or_create_totp_secret(email_in)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")

    canon = canonical_email_for_user(email_in) or email_in
    totp_uri = totp_provisioning_uri(secret, canon, issuer="AFP App")

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for easy display
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return {
        "email": canon,
        "secret": secret,  # For manual entry if needed
        "qr_code_base64": f"data:image/png;base64,{img_str}",
        "totp_uri": totp_uri,
        "instructions": "Scan the QR code with Google Authenticator app, or manually enter the secret",
    }