class KeyExchangeResponse:
    def __init__(self):
        self.auth_token = None
        self.server_session_public_key = None
        self.expire_time = None
        self.requires_otp = False
        self.terminal_key = None

    def get_terminal_key(self):
        return self.terminal_key

    def set_terminal_key(self, terminal_key):
        self.terminal_key = terminal_key

    def is_requires_otp(self):
        return self.requires_otp

    def set_requires_otp(self, requires_otp):
        self.requires_otp = requires_otp

    def get_auth_token(self):
        return self.auth_token

    def set_auth_token(self, auth_token):
        self.auth_token = auth_token

    def get_server_session_public_key(self):
        return self.server_session_public_key

    def set_server_session_public_key(self, server_session_public_key):
        self.server_session_public_key = server_session_public_key

    def get_expire_time(self):
        return self.expire_time

    def set_expire_time(self, expire_time):
        self.expire_time = expire_time
