from dto import JSONDataTransform, KeyExchangeResponse, SystemResponse
from dto.PhoenixResponseCodes import PhoenixResponseCodes
from utils import  Constants, HttpUtil,UtilMethods
from utils.AuthUtils import AuthUtils
from dto.JSONDataTransform import JSONDataTransform
from dto.PaymentRequest import PaymentRequest
import uuid
import key_exchange


endpointUrl = Constants.ROOT_LINK + "sente/accountBalance"

if __name__ == '__main__':

    endpointUrl = endpointUrl + "?terminalId=" + Constants.TERMINAL_ID + "&requestReference=" + str(uuid.uuid4())

    print(f"Balance Request:: {endpointUrl}")

    additionalData = ""

    keyxchange_response = key_exchange.do_key_exchange()

    if keyxchange_response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
        authToken  = keyxchange_response['response']['sessionAuthToken']
        sessionKey = keyxchange_response['response']['sessionKey']

        headers = AuthUtils.generate_interswitch_auth(Constants.GET_REQUEST, endpointUrl, additionalData, authToken, sessionKey)

    print(f"\n\n Balance headers...{headers}")

    print("\n\nSending Balance req...")
    response= HttpUtil.get_http_request(endpointUrl, headers)
        
    print(f"\nBalance Raw Response:: {response}")
    payment_response = UtilMethods.unmarshall_system_response_object(response)
    
    print(f"\nBalance Unmarshalled Response:: {payment_response}")

