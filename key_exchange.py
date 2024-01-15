import json
import uuid
from dto.KeyExchangeResponse import KeyExchangeResponse
from dto.PhoenixResponseCodes import PhoenixResponseCodes
from utils import AuthUtils, Constants,HttpUtil, UtilMethods
from utils.CryptoUtils import CryptoUtils
from utils.AuthUtils import AuthUtils
from utils.key_util import private_key as client_private_key
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
from utils.key_util import private_key as privateKeyObj
from utils.CryptoUtils import CryptoUtils

endpoint_url = Constants.ROOT_LINK + "client/doKeyExchange"


def do_key_exchange():
    
    private_key = Constants.PRIKEY
    public_key  = Constants.PUBKEY
    key = privateKeyObj

    curve_private_key, curve_public_key, private_c_key = CryptoUtils.get_curve_key_pair()

    req_reference = uuid.uuid4().hex
    request = KeyExchangeResponse()

    request.terminal_id = Constants.TERMINAL_ID
    request.serial_id = Constants.MY_SERIAL_ID
    request.request_reference = req_reference #uuid.uuid4().hex
    request.app_version = Constants.APP_VERSION
    hashed_password_hex = UtilMethods.hash512(Constants.ACCOUNT_PWD.strip())
    base64_encoded_hash = b64encode(bytes.fromhex(hashed_password_hex)).decode('utf-8')
    password_cipher     = base64_encoded_hash + request.request_reference + Constants.MY_SERIAL_ID
    request.password    = CryptoUtils.sign_with_private(password_cipher,key)
    request.client_session_public_key = curve_public_key

    print(f"key exchange password hash {base64_encoded_hash}")
    print(f"key exchange password cipher {password_cipher}")
   
    headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, endpoint_url, "", "", "", private_key)
   
    request_dict = {
        "terminalId": request.terminal_id,
        "serialId": request.serial_id,
        "requestReference": request.request_reference,
        "appVersion": request.app_version,
        "password": request.password,
        "clientSessionPublicKey": request.client_session_public_key,
    }

    json_data = json.dumps(request_dict)
    
    # Print statements for debugging
    print("Ready for json data")
    print("The json data:", json_data)
    print("The headers:", headers)

    response = HttpUtil.post_http_request(endpoint_url, headers, json_data)

    # Print the response for debugging
    print("The server response:", response)

    keyxchange_response = UtilMethods.unmarshall_system_response_object(response) #KeyExchangeResponse
    
    if keyxchange_response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
       
        decrypted_session_key = CryptoUtils.decrypt_with_private(keyxchange_response['response']['serverSessionPublicKey'],private_key)
        shared_key      = CryptoUtils.make_shared_key(curve_private_key,decrypted_session_key,private_c_key)
        sharedKeyBase64 = b64encode(shared_key)
        keyxchange_response['response']['sessionKey'] = sharedKeyBase64.decode('utf-8')

        if keyxchange_response['response']['authToken']:
            keyxchange_response['response']['sessionAuthToken'] = CryptoUtils.decrypt_with_private(keyxchange_response['response']['authToken'],private_key)

        print(f"Key Exchange Response:{keyxchange_response}")
        return keyxchange_response
    else:
        raise ValueError(keyxchange_response['responseCode'], keyxchange_response['responseMessage'])

do_key_exchange()