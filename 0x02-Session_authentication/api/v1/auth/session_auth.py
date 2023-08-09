#!/usr/bin/env python3
"""Session auth"""


from api.v1.auth.auth import Auth
import uuid
from typing import TypeVar
from models.user import User


class SessionAuth(Auth):
    """Handling Sessions as an authentication"""
    user_id_by_session_id: dict = {}

    def create_session(self, user_id: str = None) -> str:
        """creates a session ID for a given user_id"""
        if user_id is None or not isinstance(user_id, str):
            return None
        sess_id = uuid.uuid4()
        self.user_id_by_session_id[str(sess_id)] = user_id
        return str(sess_id)

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns a User Id based on a session_id"""
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)
