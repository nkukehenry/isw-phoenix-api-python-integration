from dto.LoginResponse import LoginResponse


class SystemResponse:
    def __init__(self):
        self.responseCode = ""
        self.responseMessage = ""
        self.response = None

class SystemResponseLoginResponse(SystemResponse):
    def __init__(self):
        super().__init__()
        self.response = LoginResponse()

