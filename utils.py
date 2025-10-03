import hashlib, os, secrets
from database import engine
import models


def generate_salt() -> str:
    """Generate a random salt for password hashing"""
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    """Hash a password with the given salt"""
    hashed = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode(), 
        salt.encode(), 
        100000
    ).hex()
    return hashed


def verify_password(stored_hash: str, salt: str, password: str) -> bool:
    """Verify a password against its hash and salt"""
    password_hash = hash_password(password, salt)
    return password_hash == stored_hash


def init_db():
    models.Base.metadata.create_all(bind=engine)
