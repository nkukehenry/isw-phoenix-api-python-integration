class PaymentsTerminalRequest:
    def __init__(self):
        self.terminalId = ""
        self.requestReference = ""
        self.IIN = ""
        self.gprsCoordinate = ""

    def getTerminalId(self):
        return self.terminalId

    def setTerminalId(self, terminalId):
        self.terminalId = terminalId

    def getRequestReference(self):
        return self.requestReference

    def setRequestReference(self, requestReference):
        self.requestReference = requestReference

    def getIIN(self):
        return self.IIN

    def setIIN(self, IIN):
        self.IIN = IIN

    def getGprsCoordinate(self):
        return self.gprsCoordinate

    def setGprsCoordinate(self, gprsCoordinate):
        self.gprsCoordinate = gprsCoordinate
