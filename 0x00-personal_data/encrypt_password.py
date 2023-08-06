#!/usr/bin/env python3
"""encrypt a password
"""
import bcrypt
from bcrypt import hashpw, checkpw


def hash_password(password: str) -> bytes:
    """ a function to return an encrypted password"""
    passwd = password.encode()
    hashed = hashpw(passwd, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ a function to check the validity of a password"""
    return bcrypt.checkpw(password.encode(), hashed_password)
