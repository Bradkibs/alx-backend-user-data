#!/usr/bin/env python3
"""Setting up a User SQLAlchemy model"""


from sqlalchemy import Column, Integer, String


class User:
    """A class that models a user"""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, nullable=False)
    email = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    session_id = Column(String, nullable=True)
    reset_token = Column(String, nullable=True)
