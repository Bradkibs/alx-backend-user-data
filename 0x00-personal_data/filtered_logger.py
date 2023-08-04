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


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Method of filtering values and formatting them"""
        log_msg = record.getMessage()
        obfuscated_msg = filter_datum(self.fields,
                                      self.REDACTION, log_msg, self.SEPARATOR)
        record.msg = obfuscated_msg
        return super().format(record)
