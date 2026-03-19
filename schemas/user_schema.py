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
    customer_id: str = Field(..., description="MongoDB customer _id as string")
    type: str = Field(..., description='Scan type: "IN" or "OUT"')

class BaseResponse(BaseModel):
    message: str
    status_code: int = Field(..., description="The status code of the response")

class UserResponse(BaseResponse):
    token: Optional[str] = Field(None, description="JWT token if login successful")
    requires_otp: Optional[bool] = Field(None, description="True if OTP verification required")
    risk_factors: Optional[List[str]] = Field(None, description="List of risk factors detected")