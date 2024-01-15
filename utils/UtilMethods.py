import base64
import hashlib
import logging
import os
import random
import re
from typing import TypeVar
import json

import hexbytes
from requests.exceptions import RequestException

from dto.SystemResponse import SystemResponse
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes


T = TypeVar('T')
logger = logging.getLogger(__name__)


class SystemApiException(RequestException):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(message)


def hash512(plaintext: str) -> str:
    try:
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(plaintext.encode('utf-8'))
        hashed_data = digest.finalize()
        return hashed_data.hex()
    except Exception as e:
        logger.error("Exception trace: {}".format(str(e)))
        raise SystemApiException("InternalError", "Failure to hash512 object")


def unmarshall_system_response_object(response) -> SystemResponse:
    try:
        obj = json.loads(response)
        #return SystemResponse(**obj)
        return obj
    except Exception as e:
        logger.error("Exception trace: {}".format(str(e)))
        raise SystemApiException("InternalError", "Failure to unmarshall json string from systemresponse object")


def random_bytes_hex_encoded(count: int) -> str:
    try:
        bytes_obj = os.urandom(count)
        hex_str = hexbytes.HexBytes(bytes_obj).hex()
        return hex_str
    except Exception as e:
        logger.error("Exception trace: {}".format(str(e)))
        return None


def is_empty_string(string: str, default_return: str) -> str:
    return string if not is_empty(string) else default_return


def is_empty(string: str) -> bool:
    return (not string) or (string.strip().lower() in ['null', 'none', 'nil', '']) 
