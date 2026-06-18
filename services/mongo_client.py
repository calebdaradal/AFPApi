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


def get_database(db_name: str):  # added: allow selecting a specific database by name (e.g., "vpc") for testing endpoints
    """Return a database instance by name using the shared MongoClient."""  # added: docstring for new helper
    return _client[db_name]  # added: reuse existing client and select requested database


def get_users_collection():
    """Return the users collection for auth (email, password_hash)."""
    return _db["users"]


def get_customers_collection():
    """Return the customers collection for customer records."""
    return _db["customers"]


def get_records_collection():
    """Return the records collection for IN/OUT scan logs."""
    return _db["records"]


def get_passcards_collection():  # added: new MongoDB collection helper for passcards (new VPC schema)
    return _db["passcards"]  # added: return passcards collection


def get_owners_collection():  # added: new MongoDB collection helper for owners (new VPC schema)
    return _db["owners"]  # added: return owners collection


def get_vehicles_collection():  # added: new MongoDB collection helper for vehicles (new VPC schema)
    return _db["vehicles"]  # added: return vehicles collection
