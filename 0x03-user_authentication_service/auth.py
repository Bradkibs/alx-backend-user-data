#!/usr/bin/env python3
"""Hashing the password method"""

import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import SQLAlchemyError
from uuid import uuid4
from typing import TypeVar
from user import User


def _hash_password(password: str) -> str:
    """takes in the password and returns bytes of a salted hash"""
    salt = bcrypt.gensalt()
    hashed_pass = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pass.decode('utf-8')


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registering a user and making sure that the user is valid"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            passw = _hash_password(password)
            new_user = self._db.add_user(email=email, hashed_password=passw)
            return new_user
