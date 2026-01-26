from pydantic_settings import BaseSettings

class AppSettings(BaseSettings):
    app_name: str = "Development API"
    debug: bool = True
    rate_limit: str = "1/minute"

    class Config:
        env_file = ".env"