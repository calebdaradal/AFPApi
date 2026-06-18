from fastapi import APIRouter, HTTPException, Request, Header
from fastapi.responses import StreamingResponse
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
from services.user_service import validate_user, hash_password, find_user_by_email, get_user_email  # changed: support new Mongo user schema fields (Email/Security)
from services.mongo_client import (  # changed: include new VPC schema collections
    get_users_collection,  # unchanged: users collection helper
    get_customers_collection,  # unchanged: legacy customers helper (not used by new scan flow)
    get_records_collection,  # unchanged: legacy records helper (not used by new scan flow)
    get_database,  # unchanged: debug helper
    get_passcards_collection,  # added: passcards collection helper for new scan flow
    get_owners_collection,  # added: owners collection helper for new scan flow
    get_vehicles_collection,  # added: vehicles collection helper for new scan flow
)  # changed: end import list
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
from services.s3_client import resolve_vehicle_object_key, resolve_passcard_document_object_key, presign_get_object, get_s3_client  # changed: add passcard document S3 resolver (d_or/{FileName})
from services.jwt_service import create_jwt_token, verify_jwt_token
from core.config import AppSettings
from core.rate_limit import limiter
from loguru import logger

router = APIRouter()
settings = AppSettings()

_OTP_NUDGE_DAYS = 30


def _maybe_refresh_periodic_otp_prompt(users, email_canon: str) -> None:
    """If OTP is off and user dismissed setup, re-prompt after [_OTP_NUDGE_DAYS]."""
    user = find_user_by_email(users, email_canon)  # changed: support both `email` and `Email` user schemas
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
    if due:  # changed: keep behavior and update by _id to avoid schema field-name mismatch
        users.update_one({"_id": user["_id"]}, {"$set": {"otp_setup_prompt_pending": True}})  # changed: update by _id for schema compatibility


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
    if isinstance(value, datetime):  # added: ensure datetimes from Mongo can be returned in JSON responses
        return value.isoformat()  # added: represent datetimes as ISO-8601 strings for JSON safety
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
    user = find_user_by_email(users, email)  # changed: support both legacy (`email`) and new (`Email`) schemas
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    email = get_user_email(user) or email  # added: normalize email to stored value for downstream consistency
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
    existing = find_user_by_email(users, payload.email)  # changed: check both `email` and `Email` fields
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = hash_password(payload.password)
    users.insert_one({  # changed: insert using new Mongo user schema (and keep app-required fields)
        "UserName": payload.email.strip(),  # added: new schema field
        "Email": payload.email.strip(),  # added: new schema field used for login
        "TenantId": "",  # added: new schema field placeholder
        "Security": {  # added: new schema security object
            "Password": password_hash,  # changed: store bcrypt hash under Security.Password
            "IsVerified": True,  # added: new schema field default
            "IsActive": True,  # added: new schema field default (used by profile)
            "Role": "",  # added: new schema field placeholder
            "ScanOnly": False,  # added: new schema field default
            "PasswordExpiry": None,  # added: new schema field default
        },  # added: end Security
        "FullName": {  # added: new schema name object
            "LastName": payload.last_name,  # added: new schema field
            "FirstName": payload.first_name,  # added: new schema field
            "MiddleName": "",  # added: new schema field placeholder
        },  # added: end FullName
        "Implementor": {"Name": ""},  # added: new schema field placeholder
        "Env": "",  # added: new schema field placeholder
        "phone_number": payload.phone_number,  # changed: keep app-required field (legacy name)
        "image": (payload.image or "").strip(),  # changed: keep app-required field
        "otp_enabled": False,  # unchanged: app feature flag stored at root
        "otp_setup_prompt_pending": True,  # unchanged: app feature flag stored at root
    })  # changed: end insert
    return {"message": "User registered successfully"}


@router.post("/user/login", response_model=UserResponse)
@limiter.limit(settings.rate_limit)
async def login_user(request: Request, payload: LoginInput):
    """
    If OTP is disabled for the user: password-only login (JWT issued).
    If OTP enabled: use risk_engine plus 7-day TOTP re-verify — non-risky and fresh → JWT; else OTP required first.
    """
    client_ip = request.client.host if request.client else "unknown"
    if settings.debug:  # added: emit detailed login attempt logs only when DEBUG=True
        logger.info(  # added: log safe login metadata (no password printed)
            "Login attempt received (email_input={!r}, client_ip={!r})",  # added: include safe context
            (payload.email or "").strip(),  # added: normalized email only
            client_ip,  # added: client ip for correlation
        )  # added: end log call
    if not validate_user(payload.email, payload.password):
        record_failed_attempt(payload.email)
        if settings.debug:  # added: emit detailed login rejection logs only when DEBUG=True
            logger.warning(  # added: log rejection without leaking password/hash
                "Login rejected: invalid credentials (email_input={!r}, client_ip={!r})",  # added: safe context only
                (payload.email or "").strip(),  # added: normalized email only
                client_ip,  # added: client ip for correlation
            )  # added: end log call
        raise HTTPException(status_code=401, detail="Invalid credentials")

    users = get_users_collection()  # unchanged: load users collection
    email_stripped = payload.email.strip()  # unchanged: normalize input
    canon = canonical_email_for_user(email_stripped) or email_stripped  # unchanged: resolve stored casing where possible
    user = find_user_by_email(users, canon)  # changed: support both `email` and `Email` user schemas
    if not user:
        raise HTTPException(status_code=500, detail="User record not found")
    canon = get_user_email(user) or canon  # added: ensure we use the stored email value for downstream logic

    _maybe_refresh_periodic_otp_prompt(users, canon)
    user = users.find_one({"_id": user["_id"]}) or user  # changed: reload by _id after possible update
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

    needs_otp = True
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

    canonical = canonical_email_for_user(email_in) or email_in  # unchanged: resolve canonical email
    users = get_users_collection()  # unchanged: load users collection
    user = find_user_by_email(users, canonical)  # added: support both `email` and `Email` user schemas
    if not user:  # added: fail clearly if user is missing
        raise HTTPException(status_code=404, detail="User not found")  # added: consistent error for missing user
    users.update_one(  # changed: update by _id for schema compatibility
        {"_id": user["_id"]},  # changed: update by _id
        {"$set": {"last_totp_verified_at": datetime.now(timezone.utc).isoformat()}},  # unchanged: store ISO timestamp
    )  # changed: end update
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
    user = find_user_by_email(users, email)  # added: load user for schema-safe updates
    if not user:  # added: fail clearly if user missing
        raise HTTPException(status_code=404, detail="User not found")  # added: consistent error for missing user
    if payload.accepted:
        get_or_create_totp_secret(email)
        users.update_one(
            {"_id": user["_id"]},  # changed: update by _id for schema compatibility
            {"$set": {"otp_enabled": True, "otp_setup_prompt_pending": False}},
        )
        path = f"user/setup-totp/{quote(email, safe='')}"
        return {
            "message": "OTP enabled. Open the URL below in a browser to scan your QR code.",
            "setup_totp_path": path,
        }
    users.update_one(  # changed: update by _id for schema compatibility
        {"_id": user["_id"]},  # changed: update by _id
        {"$set": {"otp_setup_prompt_pending": False, "otp_last_nudge_at": now_iso}},  # unchanged: store dismissal and nudge time
    )  # changed: end update
    return {"message": "Acknowledged", "setup_totp_path": None}


@router.get("/user/profile", response_model=UserProfileResponse)
@limiter.limit(settings.rate_limit)
async def get_user_profile(request: Request, authorization: Optional[str] = Header(default=None)):
    """
    Get authenticated user's profile from MongoDB.
    """
    _, user = _auth_email_and_require_fresh_totp_if_enabled(authorization)  # unchanged: load authenticated user
    raw_img = user.get("image", "")  # unchanged: image field (app-specific)
    profile_image = raw_img.strip() if isinstance(raw_img, str) else ""
    full_name = user.get("FullName") if isinstance(user.get("FullName"), dict) else {}  # added: read new schema name object safely
    security = user.get("Security") if isinstance(user.get("Security"), dict) else {}  # added: read new schema security object safely
    return UserProfileResponse(
        email=get_user_email(user),  # changed: support both `email` and `Email` fields
        first_name=user.get("first_name") or full_name.get("FirstName", ""),  # changed: prefer legacy, fallback to new schema
        last_name=user.get("last_name") or full_name.get("LastName", ""),  # changed: prefer legacy, fallback to new schema
        phone_number=user.get("phone_number", ""),  # unchanged: stored at root for app compatibility
        is_active=bool(user.get("is_active")) if "is_active" in user else bool(security.get("IsActive", False)),  # changed: map active flag from new schema
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
    email, user = _auth_email_and_require_fresh_totp_if_enabled(authorization)  # unchanged: load authenticated user
    users = get_users_collection()
    set_doc = {
        "first_name": payload.first_name,  # unchanged: keep legacy field for backward compatibility
        "last_name": payload.last_name,  # unchanged: keep legacy field for backward compatibility
        "FullName.FirstName": payload.first_name,  # added: update new schema field
        "FullName.LastName": payload.last_name,  # added: update new schema field
        "phone_number": payload.phone_number,  # unchanged: app uses this field
        "image": (payload.image or "").strip(),  # unchanged: app uses this field
    }
    if payload.otp_enabled is not None:
        set_doc["otp_enabled"] = payload.otp_enabled
        if payload.otp_enabled:
            get_or_create_totp_secret(email)
    users.update_one(
        {"_id": user["_id"]},  # changed: update by _id for schema compatibility
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
    Create an IN/OUT scan response from a scanned passcard QR code.
    """  # changed: passcards are now the scanned IDs (new VPC schema)
    _auth_email_and_require_fresh_totp_if_enabled(authorization)
    scan_type = payload.type.strip().upper()
    if scan_type not in {"IN", "OUT"}:
        raise HTTPException(status_code=400, detail='Invalid type. Use "IN" or "OUT".')
    raw_passcard_id = (payload.passcard_id or "").strip()  # added: passcard id from QR
    if not raw_passcard_id:  # added: validate required passcard id
        raise HTTPException(status_code=400, detail="passcard_id is required")  # added: consistent 400 error
    passcard_id = raw_passcard_id  # added: default to raw scan value
    if raw_passcard_id.lower().startswith("vpc:"):  # added: support new QR format: vpc:{raw passcard id}
        passcard_id = raw_passcard_id.split(":", 1)[1].strip()  # added: strip prefix and whitespace
    if not passcard_id:  # added: validate after vpc: stripping
        raise HTTPException(status_code=400, detail="passcard_id is required")  # added: consistent 400 error

    passcards = get_passcards_collection()  # added: use passcards collection for lookup
    passcard = passcards.find_one({"_id": passcard_id})  # added: primary lookup by passcard _id
    if not passcard:  # added: fallback lookup by SerialNumber
        passcard = passcards.find_one({"SerialNumber": passcard_id})  # added: support scanning serial number if used in QR
    if not passcard:  # added: not found
        raise HTTPException(status_code=404, detail="Passcard not found")  # added: consistent 404 error
    passcard_status = str(passcard.get("Status") or "").strip().upper()  # added: validate passcard status for scan eligibility
    if passcard_status == "LOST":  # changed: only block LOST passcards from scanning
        raise HTTPException(status_code=400, detail="Sorry invalid passcard")  # changed: keep same modal-triggering message
    expires_in_raw = passcard.get("ExpiresIn")  # added: passcard expiry window in days
    try:  # added: coerce expires-in into an integer
        expires_in = int(expires_in_raw) if expires_in_raw is not None and str(expires_in_raw).strip() != "" else 0  # added: default to 0 when missing
    except Exception:  # added: handle invalid expires-in values
        expires_in = 0  # added: treat invalid expires-in as no expiry
    if expires_in < 0:  # added: negative expires-in invalidates passcard immediately
        raise HTTPException(status_code=400, detail="Sorry invalid passcard")  # added: required invalid modal message
    if expires_in > 0:  # added: expiry check only when expires-in is positive
        approved_raw = passcard.get("ApprovedDate")  # added: approved date ISO string
        approved_str = str(approved_raw or "").strip()  # added: normalize approved date string
        if not approved_str:  # added: approved date required when expiry is enabled
            raise HTTPException(status_code=400, detail="Sorry invalid passcard")  # added: required invalid modal message
        try:  # added: parse ISO datetime with offset (ex: 2026-06-18T05:13:04.506+00:00)
            approved_dt = datetime.fromisoformat(approved_str)  # added: parse into datetime
        except Exception:  # added: parsing failed
            raise HTTPException(status_code=400, detail="Sorry invalid passcard")  # added: required invalid modal message
        if approved_dt.tzinfo is None:  # added: ensure timezone-aware datetime
            approved_dt = approved_dt.replace(tzinfo=timezone.utc)  # added: assume UTC when tz is missing
        expires_at = approved_dt + timedelta(days=expires_in)  # added: compute expiry datetime
        now_utc = datetime.now(timezone.utc)  # added: current UTC datetime
        if now_utc > expires_at.astimezone(timezone.utc):  # added: invalid when current date is past expiry date
            raise HTTPException(status_code=400, detail="Sorry invalid passcard")  # added: required invalid modal message

    owner_id = (passcard.get("OwnerId") or "").strip()  # added: owner id reference from passcard
    vehicle_id = (passcard.get("VehicleId") or "").strip()  # added: default vehicle id reference from passcard
    if not owner_id:  # added: validate passcard linkage
        raise HTTPException(status_code=500, detail="Passcard is missing OwnerId")  # added: data integrity error

    owners = get_owners_collection()  # added: owners collection for joined details
    owner = owners.find_one({"_id": owner_id})  # added: load owner by _id
    if not owner:  # added: owner not found
        raise HTTPException(status_code=404, detail="Owner not found")  # added: consistent 404 error

    vehicles = get_vehicles_collection()  # added: vehicles collection for joined details
    if not vehicle_id:  # added: passcard should always tie to one vehicle
        raise HTTPException(status_code=500, detail="Passcard is missing VehicleId")  # added: data integrity error
    vehicle = vehicles.find_one({"_id": vehicle_id})  # changed: each passcard maps to one specific vehicle
    if not vehicle:  # added: vehicle not found
        raise HTTPException(status_code=404, detail="Vehicle not found")  # added: consistent 404 error

    address_obj = owner.get("Address") if isinstance(owner.get("Address"), dict) else {}  # added: safely read nested address object
    rank_obj = owner.get("Rank") if isinstance(owner.get("Rank"), dict) else {}  # added: safely read nested rank object
    owner_payload = {  # added: shape owner details needed by Flutter modal
        "id": owner.get("_id", ""),  # added: owner id
        "first_name": owner.get("FirstName", ""),  # added: owner first name
        "middle_name": owner.get("MiddleName", ""),  # added: owner middle name
        "last_name": owner.get("LastName", ""),  # added: owner last name
        "rank_name": rank_obj.get("Name", ""),  # added: owner rank display name
        "mobile_no": owner.get("MobileNo", ""),  # added: owner mobile number
        "status": owner.get("Status", ""),  # added: owner status (ACTIVE/INACTIVE)
        "address": address_obj.get("Address", ""),  # added: owner address string
        "brgy_id": address_obj.get("BrgyId", ""),  # added: owner brgy id
    }  # added: end owner payload

    wheel_obj = vehicle.get("WheelType") if isinstance(vehicle.get("WheelType"), dict) else {}  # added: safely read nested wheel type object
    vehicle_file_name = (vehicle.get("FileName") or "").strip()
    vehicle_object_key = resolve_vehicle_object_key(vehicle_file_name)
    raw_documents = passcard.get("Documents") if isinstance(passcard.get("Documents"), list) else passcard.get("documents")  # added: read passcard documents (supports Documents/documents casing)
    documents = raw_documents if isinstance(raw_documents, list) else []  # added: normalize documents to a list
    d_owner_doc = None  # added: holder for the d_owner document entry
    for doc in documents:  # added: scan passcard documents list
        if not isinstance(doc, dict):  # added: skip non-object entries
            continue  # added: move to next
        doc_name = str(doc.get("Name") or "").strip().lower()  # added: normalize document Name field
        if doc_name == "d_owner":  # changed: match d_owner document (new 2nd image)
            d_owner_doc = doc  # changed: store matching document
            break  # added: stop searching after first match
    if d_owner_doc is None:  # added: fallback for older data that still uses d_or
        for doc in documents:  # added: scan passcard documents list again
            if not isinstance(doc, dict):  # added: skip non-object entries
                continue  # added: move to next
            doc_name = str(doc.get("Name") or "").strip().lower()  # added: normalize document Name field
            if doc_name == "d_or":  # added: legacy fallback
                d_owner_doc = doc  # added: reuse variable for legacy d_or
                break  # added: stop searching after first match
    d_owner_file_name = (d_owner_doc.get("FileName") or "").strip() if isinstance(d_owner_doc, dict) else ""  # changed: extract d_owner FileName
    d_owner_folder = "d_owner"  # added: default folder name for second document image
    if isinstance(d_owner_doc, dict):  # added: infer folder name from document entry when possible
        name_field = str(d_owner_doc.get("Name") or "").strip().lower()  # added: normalize name field
        if name_field in {"d_owner", "d_or"}:  # added: restrict to known folders
            d_owner_folder = name_field  # added: use detected folder
    d_owner_object_key = resolve_passcard_document_object_key(d_owner_folder, d_owner_file_name) if d_owner_file_name else ""  # changed: resolve {folder}/{FileName} key if present
    vehicle_payload = {  # added: single vehicle payload (each passcard ties to one vehicle)
        "id": vehicle.get("_id", ""),  # added: vehicle id
        "plate_number": vehicle.get("PlateNumber", ""),  # added: plate number
        "model": vehicle.get("Model", ""),  # added: model
        "color": vehicle.get("Color", ""),  # added: color
        "year_model": vehicle.get("YearModel", ""),  # added: year model
        "status": vehicle.get("Status", ""),  # added: vehicle status (ACTIVE/INACTIVE)
        "wheel_type_description": wheel_obj.get("Description", ""),  # added: wheel type description
        "file_name": vehicle_file_name,
        "s3_key": vehicle_object_key,
        "image_found": bool(vehicle_object_key),
        "image_url": presign_get_object(vehicle_object_key, expires_seconds=300) if vehicle_object_key else "",
        "image_proxy_path": f"vehicle/image/{quote(vehicle_file_name, safe='')}" if vehicle_file_name else "",
        "d_owner_file_name": d_owner_file_name,  # changed: passcard document file name for d_owner
        "d_owner_folder": d_owner_folder,  # added: folder name used for the second document image (d_owner or fallback d_or)
        "d_owner_s3_key": d_owner_object_key,  # changed: resolved S3 key for d_owner document ({folder}/{FileName})
        "d_owner_image_found": bool(d_owner_object_key),  # changed: indicate if d_owner image exists in S3
        "d_owner_image_url": presign_get_object(d_owner_object_key, expires_seconds=300) if d_owner_object_key else "",  # changed: presigned URL for d_owner image
        "d_owner_image_proxy_path": f"passcard/document/{quote(d_owner_folder, safe='')}/{quote(d_owner_file_name, safe='')}" if d_owner_file_name else "",  # changed: API proxy path for streaming d_owner image
    }  # added: end vehicle payload

    now = datetime.now()  # added: scan timestamp (not persisted)
    record_data = {  # added: scan metadata for UI
        "passcard_id": passcard.get("_id", passcard_id),  # added: resolved passcard id
        "type": scan_type,  # added: IN/OUT
        "date": now.strftime("%Y-%m-%d"),  # added: scan date
        "time": now.strftime("%H:%M:%S"),  # added: scan time
    }  # added: end record

    passcard_payload = {  # added: passcard details for owner section labels
        "id": passcard.get("_id", passcard_id),  # added: passcard id
        "category": passcard.get("Category", ""),  # added: passcard category
        "category_eligibility": passcard.get("CategoryEligibility", ""),  # added: passcard category eligibility
        "category_specification": passcard.get("CategorySpecification", ""),  # added: passcard category specification
    }  # added: end passcard payload

    response_payload = {  # added: response expected by Flutter after scanning
        "message": "Scan successful",  # added: success message
        "record": record_data,  # added: scan metadata
        "owner": owner_payload,  # added: owner details
        "vehicle": vehicle_payload,  # changed: single vehicle tied to the passcard
        "passcard": passcard_payload,  # added: passcard details for UI labels
        "passcard_status": passcard_status,  # changed: normalized passcard status
    }  # added: end response
    return _to_json_safe(response_payload)  # changed: ensure JSON-safe types


@router.get("/vehicle/image/{filename}")
@limiter.limit(settings.rate_limit)
async def get_vehicle_image(request: Request, filename: str):  # changed: include request for slowapi rate limiter
    name = (filename or "").strip().lstrip("/")
    if not name:
        raise HTTPException(status_code=400, detail="filename is required")
    key = resolve_vehicle_object_key(name)
    if not key:
        raise HTTPException(status_code=404, detail="Image not found")
    client = get_s3_client()
    try:
        obj = client.get_object(Bucket=settings.bucket_name, Key=key)
    except Exception:
        raise HTTPException(status_code=404, detail="Image not found")
    body = obj.get("Body")
    content_type = obj.get("ContentType") or "application/octet-stream"
    if content_type == "application/octet-stream":
        lower = key.lower()
        if lower.endswith(".jpg") or lower.endswith(".jpeg"):
            content_type = "image/jpeg"
        elif lower.endswith(".png"):
            content_type = "image/png"
        elif lower.endswith(".webp"):
            content_type = "image/webp"
    return StreamingResponse(body, media_type=content_type)


@router.get("/passcard/document/{doc_name}/{filename}")  # changed: stream passcard document images from S3 (ex: d_owner/{FileName})
@limiter.limit(settings.rate_limit)  # added: keep consistent rate limiting
async def get_passcard_document_image(request: Request, doc_name: str, filename: str):  # added: handler for passcard document image proxy
    folder = (doc_name or "").strip().strip("/").lower()  # added: normalize folder name
    if folder not in {"d_owner", "d_or"}:  # changed: restrict to known passcard document folders (avoid arbitrary key reads)
        raise HTTPException(status_code=404, detail="Image not found")  # added: hide unsupported document folders
    name = (filename or "").strip().lstrip("/")  # added: normalize filename
    if not name:  # added: validate required filename
        raise HTTPException(status_code=400, detail="filename is required")  # added: consistent missing filename error
    key = resolve_passcard_document_object_key(folder, name)  # changed: resolve S3 key under allowed folder/
    if not key:  # added: not found
        raise HTTPException(status_code=404, detail="Image not found")  # added: consistent not found error
    client = get_s3_client()  # added: reuse singleton S3 client
    try:  # added: wrap S3 get_object
        obj = client.get_object(Bucket=settings.bucket_name, Key=key)  # added: fetch image bytes
    except Exception:  # added: map S3 errors to 404
        raise HTTPException(status_code=404, detail="Image not found")  # added: consistent not found error
    body = obj.get("Body")  # added: streaming body
    content_type = obj.get("ContentType") or "application/octet-stream"  # added: content type fallback
    if content_type == "application/octet-stream":  # added: infer basic image types when missing
        lower = key.lower()  # added: case-insensitive suffix check
        if lower.endswith(".jpg") or lower.endswith(".jpeg"):  # added: jpeg
            content_type = "image/jpeg"  # added: set jpeg content type
        elif lower.endswith(".png"):  # added: png
            content_type = "image/png"  # added: set png content type
        elif lower.endswith(".webp"):  # added: webp
            content_type = "image/webp"  # added: set webp content type
    return StreamingResponse(body, media_type=content_type)  # added: return streamed image response


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


@router.get("/test/vpc/dump")  # added: testing endpoint to dump all collections/documents from MongoDB database "vpc"
@limiter.limit(settings.rate_limit)  # added: keep consistent rate limiting for this testing endpoint
async def dump_vpc_database(request: Request):  # added: handler for returning all data inside the "vpc" database
    if not settings.debug:  # added: only allow this endpoint when DEBUG is enabled to reduce production exposure risk
        raise HTTPException(status_code=404, detail="Not found")  # added: hide the endpoint when not in debug mode
    db = get_database("vpc")  # added: select the requested database explicitly by name
    collections_data = {}  # added: container for all collection dumps
    for collection_name in db.list_collection_names():  # added: enumerate all collections in the database
        docs = list(db[collection_name].find({}))  # added: fetch all documents from the current collection
        collections_data[collection_name] = _to_json_safe(docs)  # added: convert BSON types to JSON-safe values
    return {"db": "vpc", "data": collections_data}  # added: return the full database dump payload
