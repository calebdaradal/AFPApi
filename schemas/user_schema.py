from pydantic import BaseModel, Field
from typing import Optional, List

class LoginInput(BaseModel):
    email: str = Field(..., description="The email of the user")
    password: str = Field(..., description="The password of the user")

class RegisterInput(BaseModel):
    email: str = Field(..., description="The email of the user")
    password: str = Field(..., description="The password of the user")
    first_name: str = Field(..., description="The first name of the user")
    last_name: str = Field(..., description="The last name of the user")
    phone_number: str = Field(..., description="The phone number of the user")
    image: str = Field(
        default="",
        description="Profile image: URL, data URI, or empty for default placeholder",
    )

class OTPVerificationInput(BaseModel):
    email: str = Field(..., description="The email of the user")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

class UserProfileResponse(BaseModel):
    email: str = Field(..., description="The email of the user")
    first_name: str = Field(..., description="The first name of the user")
    last_name: str = Field(..., description="The last name of the user")
    phone_number: str = Field(..., description="The phone number of the user")
    is_active: bool = Field(..., description="Whether the user account is active")
    image: str = Field(
        default="",
        description="Profile image URL or data URI; empty means use app default asset",
    )
    otp_enabled: bool = Field(
        default=False,
        description="When true, risky logins require TOTP; when false, password-only login",
    )

class UserProfileUpdateInput(BaseModel):
    first_name: str = Field(..., description="Updated first name")
    last_name: str = Field(..., description="Updated last name")
    phone_number: str = Field(..., description="Updated phone number")
    image: str = Field(
        default="",
        description="Profile image URL or data URI; empty clears to default placeholder",
    )
    otp_enabled: Optional[bool] = Field(
        default=None,
        description="If set, updates whether TOTP is used on risky logins",
    )

class CustomerCreateInput(BaseModel):
    first_name: str = Field(..., description="Customer first name")
    last_name: str = Field(..., description="Customer last name")
    address: str = Field(..., description="Customer address")
    age: int = Field(..., description="Customer age")
    car_model: str = Field(..., description="Customer car model")
    car_make: str = Field(..., description="Customer car make")
    plate_number: str = Field(..., description="Customer plate number")
    active: bool = Field(..., description="Whether customer is active")
    vehicle_color: str = Field(..., description="Customer vehicle color")
    image: str = Field(..., description="Customer image URL or base64 string")

class RecordCreateInput(BaseModel):
    passcard_id: str = Field(..., description="MongoDB passcard _id (or SerialNumber) as string")  # changed: scan IDs now come from passcards collection
    type: str = Field(..., description='Scan type: "IN" or "OUT"')  # unchanged: still IN/OUT

class BaseResponse(BaseModel):
    message: str
    status_code: int = Field(..., description="The status code of the response")

class UserResponse(BaseResponse):
    token: Optional[str] = Field(None, description="JWT token if login successful")
    requires_otp: Optional[bool] = Field(None, description="True if OTP verification required")
    risk_factors: Optional[List[str]] = Field(None, description="List of risk factors detected")
    show_otp_setup_prompt: bool = Field(
        default=False,
        description="True when client should offer optional OTP enrollment",
    )


class OtpSetupPromptInput(BaseModel):
    accepted: bool = Field(
        ...,
        description="True: enable OTP and prepare TOTP secret; false: dismiss and schedule next nudge",
    )
