#!/usr/bin/env python3
"""Hashing the password method"""

import bcrypt


def _hash_password(password: str) -> str:
    """takes in the password and returns bytes of a salted hash"""
    salt = bcrypt.gensalt()
    hashed_pass = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pass.decode('utf-8')
