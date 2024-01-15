from dto.ClientTerminalRequest import ClientTerminalRequest


class LoginRequest(ClientTerminalRequest):
    def __init__(self):
        super().__init__()
        self.password = None
        self.client_session_public_key = None

    def get_client_session_public_key(self):
        return self.client_session_public_key

    def set_client_session_public_key(self, client_session_public_key):
        self.client_session_public_key = client_session_public_key

    def get_password(self):
        return self.password

    def set_password(self, password):
        self.password = password
