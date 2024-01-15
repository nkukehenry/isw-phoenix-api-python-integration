# class LoginResponse:
#     def __init__(self):
#         self.firstname = None
#         self.lastname = None
#         self.username = None
#         self.name = None
#         self.contact = None
#         self.authToken = None
#         self.merchantId = None
#         self.userId = None
#         self.terminalId = None
#         self.active = False
#         self.location = None
#         self.operatorName = None
#         self.clientSecret = None
#         self.serverSessionPublicKey = None
#         self.requiresOtp = False
#         self.tpk = None
#         self.tpkIV = None
#         self.currencySymbol = None
#         self.currencyCode = None
class LoginResponse:
    def __init__(self):
        self.firstname = None
        self.lastname = None
        self.username = None
        self.name = None
        self.contact = None
        self.auth_token = None
        self.merchant_id = None
        self.user_id = None
        self.terminal_id = None
        self.active = False
        self.location = None
        self.operator_name = None
        self.client_secret = None
        self.server_session_public_key = None
        self.requires_otp = False
        self.tpk = None
        self.tpk_iv = None
        self.currency_symbol = None
        self.currency_code = None

    def get_currency_symbol(self):
        return self.currency_symbol

    def set_currency_symbol(self, currency_symbol):
        self.currency_symbol = currency_symbol

    def get_currency_code(self):
        return self.currency_code

    def set_currency_code(self, currency_code):
        self.currency_code = currency_code

    def get_tpk_iv(self):
        return self.tpk_iv

    def set_tpk_iv(self, tpk_iv):
        self.tpk_iv = tpk_iv

    def get_tpk(self):
        return self.tpk

    def set_tpk(self, tpk):
        self.tpk = tpk

    def get_client_secret(self):
        return self.client_secret

    def set_client_secret(self, client_secret):
        self.client_secret = client_secret

    def get_firstname(self):
        return self.firstname

    def set_firstname(self, firstname):
        self.firstname = firstname

    def get_lastname(self):
        return self.lastname

    def set_lastname(self, lastname):
        self.lastname = lastname

    def get_username(self):
        return self.username

    def set_username(self, username):
        self.username = username

    def get_name(self):
        return self.name

    def set_name(self, name):
        self.name = name

    def get_contact(self):
        return self.contact

    def set_contact(self, contact):
        self.contact = contact

    def get_auth_token(self):
        return self.auth_token

    def set_auth_token(self, token):
        self.auth_token = token

    def get_merchant_id(self):
        return self.merchant_id

    def set_merchant_id(self, merchant_id):
        self.merchant_id = merchant_id

    def get_user_id(self):
        return self.user_id

    def set_user_id(self, user_id):
        self.user_id = user_id

    def get_terminal_id(self):
        return self.terminal_id

    def set_terminal_id(self, terminal_id):
        self.terminal_id = terminal_id

    def is_active(self):
        return self.active

    def set_active(self, active):
        self.active = active

    def get_location(self):
        return self.location

    def set_location(self, location):
        self.location = location

    def get_operator_name(self):
        return self.operator_name

    def set_operator_name(self, operator_name):
        self.operator_name = operator_name

    def is_requires_otp(self):
        return self.requires_otp

    def set_requires_otp(self, requires_otp):
        self.requires_otp = requires_otp

    def get_server_session_public_key(self):
        return self.server_session_public_key

    def set_server_session_public_key(self, server_session_public_key):
        self.server_session_public_key = server_session_public_key

