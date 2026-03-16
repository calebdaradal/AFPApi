from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    app_name: str = "Development API"
    debug: bool = True
    rate_limit: str = "1/minute"
    # MongoDB - read from .env (MONGODB_URI, MONGODB_DB)
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db: str = "afp"

    class Config:
        env_file = ".env"