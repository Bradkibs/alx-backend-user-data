#!/usr/bin/env python3
"""A regex datum filter to return obfuscated sensitive info in logs"""


import logging
import re
from typing import List


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """A function that returns the log message obfuscated"""
    for field in fields:
        message = re.sub(r'(?<={0}{1}=)[^{0}]+'.format(separator, field),
                         redaction, message)
    return message
