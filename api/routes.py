from fastapi import APIRouter, HTTPException, Request
from schemas.user_schema import UserInput, UserResponse, OTPVerificationInput
from services.user_service import validate_user, hash_password
from services.mongo_client import get_users_collection
from services.risk_engine import analyze_risk, record_failed_attempt, record_successful_login
from services.totp_service import generate_totp_secret, verify_totp
from services.jwt_service import create_jwt_token
from core.config import AppSettings
from core.rate_limit import limiter

router = APIRouter()
settings = AppSettings()


@router.post("/user/register")
@limiter.limit(settings.rate_limit)
async def register_user(request: Request, payload: UserInput):
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
        "is_active": True,
    })
    return {"message": "User registered successfully"}


@router.post("/user/login", response_model=UserResponse)
@limiter.limit(settings.rate_limit)
async def login_user(request: Request, payload: UserInput):
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