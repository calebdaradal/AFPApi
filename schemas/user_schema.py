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

class OTPVerificationInput(BaseModel):
    email: str = Field(..., description="The email of the user")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

class UserProfileResponse(BaseModel):
    email: str = Field(..., description="The email of the user")
    first_name: str = Field(..., description="The first name of the user")
    last_name: str = Field(..., description="The last name of the user")
    phone_number: str = Field(..., description="The phone number of the user")
    is_active: bool = Field(..., description="Whether the user account is active")

class UserProfileUpdateInput(BaseModel):
    first_name: str = Field(..., description="Updated first name")
    last_name: str = Field(..., description="Updated last name")
    phone_number: str = Field(..., description="Updated phone number")

class BaseResponse(BaseModel):
    message: str
    status_code: int = Field(..., description="The status code of the response")

class UserResponse(BaseResponse):
    token: Optional[str] = Field(None, description="JWT token if login successful")
    requires_otp: Optional[bool] = Field(None, description="True if OTP verification required")
    risk_factors: Optional[List[str]] = Field(None, description="List of risk factors detected")