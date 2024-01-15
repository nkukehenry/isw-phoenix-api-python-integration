from dto import JSONDataTransform, KeyExchangeResponse, SystemResponse
from dto.PhoenixResponseCodes import PhoenixResponseCodes
from utils import  Constants, HttpUtil,UtilMethods
from utils.AuthUtils import AuthUtils
from dto.JSONDataTransform import JSONDataTransform
from dto.PaymentRequest import PaymentRequest
import uuid
import key_exchange


def get_biller_categories():

    endpointUrl = Constants.BILLERS_BASE_URL + f"categories-by-client/{Constants.TERMINAL_ID}/{Constants.TERMINAL_ID}"
    print(f" Request URL:: {endpointUrl}")

    additionalData = ""
    keyxchange_response = key_exchange.do_key_exchange()

    if keyxchange_response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
        authToken  = keyxchange_response['response']['sessionAuthToken']
        sessionKey = keyxchange_response['response']['sessionKey']

        headers = AuthUtils.generate_interswitch_auth(Constants.GET_REQUEST, endpointUrl, additionalData, authToken, sessionKey)

    print(f"\n\n REQ headers...{headers}")

    print("\n\nSending  req...")
    response= HttpUtil.get_http_request(endpointUrl, headers)
        
    print(f"\nBillers Raw Response:: {response}")
    json_response = UtilMethods.unmarshall_system_response_object(response)
    
    print(f"\nBillers Unmarshalled Response:: {json_response}")
    
    return json_respon

def get_billers_in_category(categoryId):

    endpointUrl = Constants.BILLERS_BASE_URL + f"biller-by-category/{categoryId}"
    print(f" Request URL:: {endpointUrl}")

    additionalData = ""
    keyxchange_response = key_exchange.do_key_exchange()

    if keyxchange_response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
        authToken  = keyxchange_response['response']['sessionAuthToken']
        sessionKey = keyxchange_response['response']['sessionKey']

        headers = AuthUtils.generate_interswitch_auth(Constants.GET_REQUEST, endpointUrl, additionalData, authToken, sessionKey)

    print(f"\n\n REQ headers...{headers}")

    print("\n\nSending  req...")
    response= HttpUtil.get_http_request(endpointUrl, headers)
        
    print(f"\nBillers Raw Response:: {response}")
    json_response = UtilMethods.unmarshall_system_response_object(response)
    
    print(f"\nBillers Unmarshalled Response:: {json_response}")
    
    return json_respon

def get_biller_payment_items(billerId):

    endpointUrl = Constants.BILLERS_BASE_URL + f"items/biller-id/{billerId}"
    print(f" Request URL:: {endpointUrl}")

    additionalData = ""
    keyxchange_response = key_exchange.do_key_exchange()

    if keyxchange_response['responseCode'] == PhoenixResponseCodes.APPROVED.value[0]:
        authToken  = keyxchange_response['response']['sessionAuthToken']
        sessionKey = keyxchange_response['response']['sessionKey']

        headers = AuthUtils.generate_interswitch_auth(Constants.GET_REQUEST, endpointUrl, additionalData, authToken, sessionKey)

    print(f"\n\n REQ headers...{headers}")

    print("\n\nSending  req...")
    response= HttpUtil.get_http_request(endpointUrl, headers)
        
    print(f"\nBillers Raw Response:: {response}")
    json_response = UtilMethods.unmarshall_system_response_object(response)
    
    print(f"\nBillers Unmarshalled Response:: {json_response}")
    
    return json_response

#Testing Code

#get_biller_categories() # Get biller categories
#get_billers_in_category(100058) #Fetch Billers in a category by category.id
get_biller_payment_items(90561) #Fetch Payment items under a Billers by biller.id

