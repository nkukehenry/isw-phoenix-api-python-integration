from dto.ClientTerminalRequest import ClientTerminalRequest


class LoginOtpValidationRequest(ClientTerminalRequest):
    def __init__(self):
        super().__init__()
        self.otp = None

    def get_otp(self):
        return self.otp

    def set_otp(self, otp):
        self.otp = otp
