from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from utils import Constants

private_key_str = Constants.PRIKEY

private_key = serialization.load_pem_private_key(
    private_key_str.encode('utf-8'),
    password=None,
    backend=default_backend()
)
