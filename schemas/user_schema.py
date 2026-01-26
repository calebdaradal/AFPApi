from pydantic import BaseModel, Field
from typing import Optional, List

class UserInput(BaseModel):
    email: str = Field(..., description="The email of the user")
    password: str = Field(..., description="The password of the user")

class OTPVerificationInput(BaseModel):
    email: str = Field(..., description="The email of the user")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")

class BaseResponse(BaseModel):
    message: str
    status_code: int = Field(..., description="The status code of the response")

class UserResponse(BaseResponse):
    token: Optional[str] = Field(None, description="JWT token if login successful")
    requires_otp: Optional[bool] = Field(None, description="True if OTP verification required")
    risk_factors: Optional[List[str]] = Field(None, description="List of risk factors detected")