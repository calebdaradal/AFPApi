"""
MongoDB connection and collection helpers.
Uses settings from core.config (MONGODB_URI, MONGODB_DB in .env).
"""
from pymongo import MongoClient
from core.config import AppSettings

settings = AppSettings()
# Single client instance, reused for all requests
_client = MongoClient(settings.mongodb_uri)
_db = _client[settings.mongodb_db]


def get_db():
    """Return the database instance."""
    return _db


def get_users_collection():
    """Return the users collection for auth (email, password_hash)."""
    return _db["users"]


def get_customers_collection():
    """Return the customers collection for customer records."""
    return _db["customers"]


def get_records_collection():
    """Return the records collection for IN/OUT scan logs."""
    return _db["records"]
