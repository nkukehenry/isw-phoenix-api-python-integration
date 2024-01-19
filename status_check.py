from dto import JSONDataTransform, KeyExchangeResponse, SystemResponse
from dto.PhoenixResponseCodes import PhoenixResponseCodes
from utils import  Constants, HttpUtil,UtilMethods
from utils.AuthUtils import AuthUtils
from dto.JSONDataTransform import JSONDataTransform
from dto.PaymentRequest import PaymentRequest
import uuid
import key_exchange



def check_tran_status(request_ref):

    baseUrl     = Constants.ROOT_LINK + "sente/status"
    endpointUrl = baseUrl + "?terminalId=" + Constants.TERMINAL_ID + "&requestReference=" + request_ref

    print(f" Status Check Request to:: {endpointUrl}")

    additionalData = ""

    keyxchange_response = key_exchange.do_key_exchange()

    if keyxchange_response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
        authToken  = keyxchange_response['response']['sessionAuthToken']
        sessionKey = keyxchange_response['response']['sessionKey']

        headers = AuthUtils.generate_interswitch_auth(Constants.GET_REQUEST, endpointUrl, additionalData, authToken, sessionKey)

    print(f"\n\n Status Check headers...{headers}")

    print("\n\nSending  Status Check req...")
    response= HttpUtil.get_http_request(endpointUrl, headers)
        
    print(f"\ Status Check Raw Response:: {response}")
    payment_response = UtilMethods.unmarshall_system_response_object(response)
    
    print(f"\ Status Check Unmarshalled Response:: {payment_response}")


#Trigger status check, provider tran request ref as arg
check_tran_status("988998398398398")

