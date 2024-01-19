import base64
import os
from base64 import b64encode

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.backends import default_backend,openssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends.openssl import backend
from utils.key_util import private_key as privateKeyObj
from utils import Constants
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from utils.UtilMethods import SystemApiException
from dto.PhoenixResponseCodes import PhoenixResponseCodes


class CryptoUtils:

    @staticmethod
    def decrypt_with_private(data, private_key):
        try:
            # Load the private key
            pkey = privateKeyObj

            # Decode the base64-encoded client secret
            decoded_secret =  base64.b64decode(data.encode('UTF-8'))
            
            # Decrypt the client secret
            decrypted_secret = pkey.decrypt(
                decoded_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return decrypted_secret.decode('utf-8')
        
        except Exception as e:
            print(f"Error decrypting client secret: {e}")
            return None

    @staticmethod
    def encrypt_with_private(plaintext, private_key):
        try:
            private_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(
                privateKeyObj, hashAlgo=SHA256, mgfunc=lambda x, y: x + y)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            print('Exception trace:', e)
            raise SystemApiException(
                PhoenixResponseCodes.INTERNAL_ERROR.CODE, "Failure to encryptWithPrivate ")

    @staticmethod
    def sign_with_private(data, private_key):
            private_key = privateKeyObj
            data_bytes = data.encode('utf-8')
            signature = private_key.sign(
                data_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_with_public_key(data, signature):
        # Convert the public key string to bytes
        public_key_bytes = Constants.PUBKEY.encode('utf-8')

        # Load the public key
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

        # Convert the signature from base64 to bytes
        signature_bytes = base64.b64decode(signature)

        # Verify the signature
        try:
            public_key.verify(
                signature_bytes,
                data.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True  # Signature is valid
        except Exception as e:
            print(f"Signature is invalid: {e}")
            return False  # Signature is invalid

    @staticmethod
    def get_curve_key_pair():
        # Generate a SECP256R1 private key
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Get the private key's raw components
        private_numbers = private_key.private_numbers()

        # Get the private key's d value (raw scalar value)
        d = private_numbers.private_value

        d_bytes = d.to_bytes((d.bit_length() + 7) // 8, byteorder='big')

        # Get the corresponding public key
        public_key = private_key.public_key()

        # Get the public key's raw components
        public_numbers = public_key.public_numbers()

        # Get the public key's Q value (raw point value)
        Q = public_numbers.public_key().public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

        # Convert the Q value to a byte array
        Q_bytes = Q

        privateCurve = base64.b64encode(d_bytes).decode("utf-8")
        publicCurve  = base64.b64encode(Q_bytes).decode("utf-8")
        privateCKey  = private_key

        return privateCurve, publicCurve, private_key

    @staticmethod
    def make_shared_key(curve_private_key,decrypted_session_key,private_c_key):
        new_curve_private = curve_private_key.encode('UTF-8')
        new_curve_public  = decrypted_session_key
        
        init = ec.derive_private_key(
            int.from_bytes(new_curve_private, byteorder='big'),
            ec.SECP256R1(),  # You may need to adjust the curve based on your requirements
            default_backend()
        )
        
        doPhase = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),  # You may need to adjust the curve based on your requirements
            base64.b64decode(new_curve_public)
            )
        return private_c_key.exchange(ec.ECDH(), doPhase)

    @staticmethod
    def encrypt_with_aes(inputStr, session_key_base64,is_base64:bool=True):
        iv = os.urandom(16)
        session_key_bytes = base64.b64decode(session_key_base64)

        print(f"To be encrypted: {inputStr}")

         # Convert plaintext to bytes
        if(is_base64):
            plaintext_bytes  = inputStr.encode('utf-8')
        else:
            plaintext_bytes  = inputStr.encode('utf-8')
       
        # Pad the plaintext using PKCS7
        padder = sympadding.PKCS7(128).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(session_key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        combined_buffer = iv + ciphertext
        return base64.b64encode(combined_buffer).decode('utf-8')

    @staticmethod
    def encrypt_password(hashed_password_hex, session_key_base64):
        iv = os.urandom(16)
        session_key_bytes = base64.b64decode(session_key_base64)

        print(f"Password: {hashed_password_hex}")

        base64_encoded_hash = base64.b64encode(bytes.fromhex(hashed_password_hex)).decode('utf-8')
        print("hashed_password_hex:", hashed_password_hex)
        print("base64_encoded_hash:", base64_encoded_hash)

        # Convert plaintext to bytes
        plaintext_bytes =  base64_encoded_hash.encode('utf-8')

        # Pad the plaintext using PKCS7
        padder = sympadding.PKCS7(128).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(session_key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        combined_buffer = iv + ciphertext

        return base64.b64encode(combined_buffer).decode('utf-8')