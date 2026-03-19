from fastapi import APIRouter, HTTPException, Request, Header
from typing import Optional
from datetime import datetime
import base64
import binascii
import hashlib
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
)
from services.user_service import validate_user, hash_password
from services.mongo_client import get_users_collection, get_customers_collection, get_records_collection
from services.risk_engine import analyze_risk, record_failed_attempt, record_successful_login
from services.totp_service import generate_totp_secret, verify_totp
from services.jwt_service import create_jwt_token, verify_jwt_token
from core.config import AppSettings
from core.rate_limit import limiter

router = APIRouter()
settings = AppSettings()


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
    })
    return {"message": "User registered successfully"}


@router.post("/user/login", response_model=UserResponse)
@limiter.limit(settings.rate_limit)
async def login_user(request: Request, payload: LoginInput):
    """
    Login endpoint with risk analysis
    Returns 200 with JWT if no risk, 202 if risky (requires OTP)
    """
    # Get client IP address for risk analysis
    client_ip = request.client.host if request.client else "unknown"
    
    # Validate user credentials first
    if not validate_user(payload.email, payload.password):
        # Record failed attempt for risk analysis
        record_failed_attempt(payload.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Run risk analysis
    risk_analysis = analyze_risk(payload.email, client_ip)
    
    # If no risk, issue JWT token directly
    if not risk_analysis["is_risky"]:
        # Record successful login
        record_successful_login(payload.email, client_ip)
        # Generate JWT token
        token = create_jwt_token(payload.email)
        return UserResponse(
            message="Login successful",
            status_code=200,
            token=token,
            requires_otp=False
        )
    
    # If risky, require OTP verification
    # Generate TOTP secret if user doesn't have one
    from services.totp_service import get_totp_secret
    if not get_totp_secret(payload.email):
        generate_totp_secret(payload.email)
    
    return UserResponse(
        message="OTP verification required",
        status_code=202,
        requires_otp=True,
        risk_factors=risk_analysis["risk_factors"]
    )

@router.post("/user/verify-otp", response_model=UserResponse)
@limiter.limit(settings.rate_limit)
async def verify_otp(request: Request, payload: OTPVerificationInput):
    """
    Verify OTP code and issue JWT token
    """
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Verify OTP code
    if not verify_totp(payload.email, payload.otp_code):
        raise HTTPException(status_code=401, detail="Invalid OTP code")
    
    # OTP verified successfully
    # Record successful login
    record_successful_login(payload.email, client_ip)
    # Generate and return JWT token
    token = create_jwt_token(payload.email)
    return UserResponse(
        message="OTP verified successfully",
        status_code=200,
        token=token,
        requires_otp=False
    )


@router.get("/user/profile", response_model=UserProfileResponse)
@limiter.limit(settings.rate_limit)
async def get_user_profile(request: Request, authorization: Optional[str] = Header(default=None)):
    """
    Get authenticated user's profile from MongoDB.
    """
    email = _get_email_from_authorization(authorization)
    users = get_users_collection()
    user = users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserProfileResponse(
        email=user.get("email", ""),
        first_name=user.get("first_name", ""),
        last_name=user.get("last_name", ""),
        phone_number=user.get("phone_number", ""),
        is_active=user.get("is_active", False),
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
    email = _get_email_from_authorization(authorization)
    users = get_users_collection()
    user = users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    users.update_one(
        {"email": email},
        {
            "$set": {
                "first_name": payload.first_name,
                "last_name": payload.last_name,
                "phone_number": payload.phone_number,
            }
        },
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
    _get_email_from_authorization(authorization)
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
    Set up TOTP for a user and return QR code URI
    Use this to add the account to Google Authenticator
    """
    from services.totp_service import generate_totp_secret, get_totp_uri
    import qrcode
    import io
    import base64
    
    # Generate TOTP secret if user doesn't have one
    secret = generate_totp_secret(email)
    
    # Get the TOTP URI for QR code
    totp_uri = get_totp_uri(email, issuer="AFP App")
    
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
        "email": email,
        "secret": secret,  # For manual entry if needed
        "qr_code_base64": f"data:image/png;base64,{img_str}",
        "totp_uri": totp_uri,
        "instructions": "Scan the QR code with Google Authenticator app, or manually enter the secret"
    }