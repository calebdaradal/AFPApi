from pydantic import BaseModel

class ErrorResponse(BaseModel):
    status_code: int
    status_message: str