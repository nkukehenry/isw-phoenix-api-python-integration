from base64 import b64encode
from base64 import b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDH

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding 

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def gen_keys():

    # Generate the RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    mpublic_key = key.public_key()

    private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

    public_key = mpublic_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    return {
        "public_key":public_key,
        "private_key":private_key
    }

#Example usage:
key_pair = gen_keys()
print(f"\n\nprivate key\n {key_pair["private_key"]}\n\n")
print(f"\n\npublic key \n{key_pair["public_key"]}\n\n")
