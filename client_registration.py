import base64
import uuid
import secrets
import hashlib
import os

from dto import CompleteClientRegistration
from logging import getLogger
from sys import stdin


import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.asymmetric import padding 

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dto import (
    ClientRegistrationResponse, CompleteClientRegistration,
    LoginResponse, SystemResponse
)

from dto.ClientRegistrationDetail import ClientRegistrationDetail
from dto.ClientRegistrationDetailEncoder import ClientRegistrationDetailEncoder

from dto.PhoenixResponseCodes import PhoenixResponseCodes

from utils.AuthUtils import AuthUtils
from utils import Constants
from utils import HttpUtil
from utils import UtilMethods
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import b64encode
from base64 import b64decode
from cryptography.hazmat.primitives import serialization, hashes
import json
from utils.key_util import private_key as privateKeyObj
from utils.CryptoUtils import CryptoUtils


logger = getLogger("ClientRegistration")

BASE_URL = Constants.ROOT_LINK + "client/"
REGISTRATION_ENDPOINT_URL = BASE_URL + "clientRegistration"
REGISTRATION_COMPLETION_ENDPOINT_URL = BASE_URL + "completeClientRegistration"


def main():
    # Generate key pair

    private_key = Constants.PRIKEY
    public_key  = Constants.PUBKEY
    key = privateKeyObj

    print(f"\n\nprivate key {private_key}\n\n")
    print(f"\n\npublic key {public_key}\n\n")

    curve_private_key, curve_public_key, private_c_key = CryptoUtils.get_curve_key_pair()

    response = client_registration_request(public_key, curve_public_key, private_key) #private_key

    print(f"\n\n\nRemote Response: {response}\n\n\n")

    registration_response = json.loads(response)

    if registration_response['responseCode'] != PhoenixResponseCodes.APPROVED.value[0]:
        print(
            f"Client Registration failed: {registration_response['responseMessage']}"
        )
    else:
        decrypted_session_key = CryptoUtils.decrypt_with_private(registration_response['response']['serverSessionPublicKey'],privateKeyObj)
        
        print("==============terminalKey==============")
        print(f"Server session key: {decrypted_session_key}")

        shared_key = CryptoUtils.make_shared_key(curve_private_key,decrypted_session_key,private_c_key)
        sharedKey = base64.b64encode(shared_key)

        print("==============shared session key==============")
        print(f"session key: {sharedKey}")
        
        auth_token = CryptoUtils.decrypt_with_private(registration_response['response']['authToken'],privateKeyObj)
     
        transaction_reference = registration_response['response']['transactionReference']
        
        print(" OTP Set automatically as empty")
        otp = ""
        
        final_response = complete_registration(
            sharedKey, auth_token, transaction_reference, otp, private_key
        )

        response = json.loads(final_response)
        
        print(f"Complete Registration Result:  {response}")
        if response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
            client_secret =  CryptoUtils.decrypt_with_private(response['response']['clientSecret'],privateKeyObj
            )
            if client_secret and len(client_secret) > 5:
                print(f"\n\n Use this NEW Client Secret: {client_secret}")
        else:
            print(f"finalResponse: {response['responseMessage']}")

def client_registration_request(publicKey, clientSessionPublicKey, privateKey):
    setup = ClientRegistrationDetail()
    setup.setSerialId(Constants.MY_SERIAL_ID)
    setup.name = "pythonclitest"
    setup.nin = "32409081"
    setup.owner_phone_number =Constants.PHONE_NUMBER 
    setup.phone_number = Constants.PHONE_NUMBER 
    setup.public_key = publicKey
    setup.requestReference = str(uuid.uuid4())
    setup.terminalId = (Constants.TERMINAL_ID)
    setup.gprsCoordinate = ""
    setup.client_session_public_key = clientSessionPublicKey

    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, REGISTRATION_ENDPOINT_URL, "", "", "", privateKey)


    print("\n\n\n\n"+str(setup)+"\n\n\n\n")

    mjson = json.dumps(setup, cls=ClientRegistrationDetailEncoder) ##client_session_public_key

    return HttpUtil.post_http_request(REGISTRATION_ENDPOINT_URL, headers, mjson)

def complete_registration(terminal_key, auth_token, transaction_reference, otp, private_key):
    
    complete_reg = CompleteClientRegistration.CompleteClientRegistration()
    password_hash = UtilMethods.hash512(Constants.ACCOUNT_PWD.strip())
    print(f"key exchange password hash {password_hash}")

    print(f"hashed password: {password_hash}")
    complete_reg.set_terminal_id(Constants.TERMINAL_ID)
    complete_reg.set_serial_id(Constants.MY_SERIAL_ID)
    complete_reg.set_otp("")

    complete_reg.set_request_reference(str(uuid.uuid4()))
    
    encrypted_hash = CryptoUtils.encrypt_password(password_hash,terminal_key)
    print(f"encrypted hash: {encrypted_hash}")

    complete_reg.set_password(encrypted_hash)#temp_password.hexdigest()
    complete_reg.set_transaction_reference(transaction_reference)
    complete_reg.set_app_version(Constants.APP_VERSION)
    complete_reg.set_gps_coordinates("")
    
    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, REGISTRATION_COMPLETION_ENDPOINT_URL,
                                                 "", auth_token, terminal_key, private_key)
    json_string = complete_reg.toJSON()
    
    print(f"json string: {json_string}")
    return HttpUtil.post_http_request(REGISTRATION_COMPLETION_ENDPOINT_URL, headers, json_string)

    return None

if __name__ == '__main__':
    main()