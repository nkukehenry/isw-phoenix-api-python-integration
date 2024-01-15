from dto import JSONDataTransform, KeyExchangeResponse, SystemResponse
from dto.PhoenixResponseCodes import PhoenixResponseCodes
from utils import  Constants, HttpUtil,UtilMethods
from utils.AuthUtils import AuthUtils
from dto.JSONDataTransform import JSONDataTransform
from dto.PaymentRequest import PaymentRequest
import uuid
import key_exchange


endpointUrl = Constants.ROOT_LINK + "sente/customerValidation"

if __name__ == '__main__':

    request = PaymentRequest()

    request.paymentCode = 53046936951
    request.customerId  = "0708898789"
    request.requestReference = str(uuid.uuid4())
    request.terminalId   = Constants.MY_TERMINAL_ID
    request.amount       = 600
    request.currencyCode = "800"

    print(f"Validation Request:: {request}")

    additionalData = ""

    keyxchange_response = key_exchange.do_key_exchange()

    if keyxchange_response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
        authToken  = keyxchange_response['response']['sessionAuthToken']
        sessionKey = keyxchange_response['response']['sessionKey']

        headers = AuthUtils.generate_interswitch_auth(Constants.POST_REQUEST, endpointUrl, additionalData, authToken, sessionKey)

    print(f"\n\n Validation headers...{headers}")

    print("\n\nSending Validation req...")
    response= HttpUtil.post_http_request(endpointUrl, headers, JSONDataTransform.marshall(request))
        
    print(f"\nValidation Raw Response:: {response}")
    payment_response = UtilMethods.unmarshall_system_response_object(response)
    
    print(f"\nValidation Unmarshalled Response:: {payment_response}")

