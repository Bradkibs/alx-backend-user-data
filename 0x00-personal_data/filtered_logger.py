#!/usr/bin/env python3
"""A regex datum filter to return obfuscated sensitive info in logs"""


import logging
import re
from typing import List


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


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


def get_logger() -> logging.Logger:
    """Logging INFO level and should not propagate messages to
    other loggers"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)

    formatter = RedactingFormatter(list(PII_FIELDS))

    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ function to return the connector of the database"""
    username = os.environ.get('PERSONAL_DATA_DB_USERNAME', 'root')
    host = os.environ.get('PERSONAL_DATA_DB_HOST', 'localhost')
    database = os.environ.get('PERSONAL_DATA_DB_NAME' '')
    password = os.environ.get('PERSONAL_DATA_DB_PASSWORD', '')

    mydb = mysql.connector.connect(
        host=host,
        user=username,
        password=password,
        database=database
    )
    return mydb


def main():
    """main
    """
    db = get_db()
    logger = get_logger()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = cursor.column_names
    for row in cursor:
        message = "".join("{}={}; ".format(k, v) for k, v in zip(fields, row))
        logger.info(message.strip())
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
