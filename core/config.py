from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    app_name: str = "Development API"
    debug: bool = True
    rate_limit: str = "1/minute"
    # MongoDB - read from .env (MONGODB_URI, MONGODB_DB)
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db: str = "afp"
    # QR decryption seed (must match the encryptor seed for AES-256-GCM key derivation)
    qr_encryption_key: str = "AFP_TEXT_ENCRYPTOR_STATIC_DEV_KEY_V1"

    class Config:
        env_file = ".env"