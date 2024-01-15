from dto.PaymentsTerminalRequest import PaymentsTerminalRequest


class PaymentRequest(PaymentsTerminalRequest):
    def __init__(self):
        super().__init__()
        self.amount = 0.0
        self.customerId = ""
        self.phoneNumber = ""
        self.paymentCode = 0
        self.customerName = ""
        self.sourceOfFunds = ""
        self.narration = ""
        self.depositorName = ""
        self.location = ""
        self.alternateCustomerId = ""
        self.transactionCode = ""
        self.customerToken = ""
        self.additionalData = ""
        self.collectionsAccountNumber = ""
        self.pin = ""
        self.otp = ""
        self.currencyCode = ""
        self.cardData = None

    def getCardData(self):
        return self.cardData

    def setCardData(self, cardData):
        self.cardData = cardData

    def getCurrencyCode(self):
        return self.currencyCode

    def setCurrencyCode(self, currencyCode):
        self.currencyCode = currencyCode

    def getAmount(self):
        return self.amount

    def setAmount(self, amount):
        self.amount = amount

    def getCustomerId(self):
        return self.customerId

    def setCustomerId(self, customerId):
        self.customerId = customerId

    def getPhoneNumber(self):
        return self.phoneNumber

    def setPhoneNumber(self, phoneNumber):
        self.phoneNumber = phoneNumber

    def getPaymentCode(self):
        return self.paymentCode

    def setPaymentCode(self, paymentCode):
        self.paymentCode = paymentCode

    def getCustomerName(self):
        return self.customerName

    def setCustomerName(self, customerName):
        self.customerName = customerName

    def getSourceOfFunds(self):
        return self.sourceOfFunds

    def setSourceOfFunds(self, sourceOfFunds):
        self.sourceOfFunds = sourceOfFunds

    def getNarration(self):
        return self.narration

    def setNarration(self, narration):
        self.narration = narration

    def getDepositorName(self):
        return self.depositorName

    def setDepositorName(self, depositorName):
        self.depositorName = depositorName

    def getLocation(self):
        return self.location

    def setLocation(self, location):
        self.location = location

    def getAlternateCustomerId(self):
        return self.alternateCustomerId

    def setAlternateCustomerId(self, alternateCustomerId):
        self.alternateCustomerId = alternateCustomerId

    def getTransactionCode(self):
        return self.transactionCode

    def setTransactionCode(self, transactionCode):
        self.transactionCode = transactionCode

    def getCustomerToken(self):
        return self.customerToken

    def setCustomerToken(self, customerToken):
        self.customerToken = customerToken

    def getAdditionalData(self):
        return self.additionalData

    def setAdditionalData(self, additionalData):
        self.additionalData = additionalData

    def getCollectionsAccountNumber(self):
        return self.collectionsAccountNumber

    def setCollectionsAccountNumber(self, collectionsAccountNumber):
        self.collectionsAccountNumber = collectionsAccountNumber

    def getPin(self):
        return self.pin

    def setPin(self, pin):
        self.pin = pin

    def getOtp(self):
        return self.otp

    def setOtp(self, otp):
        self.otp = otp
