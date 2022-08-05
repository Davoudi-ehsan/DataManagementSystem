

PACKET_FLAG = 0x7e
SERVER_KEY = 0x1987

TRANSMISSION_DIRECTION = {
    'StoC': 0x81,
    'CtoS': 0x01
}

APDU = {
    'heartbeat': 0xDD,
    'aarq': 0x60,
    'aare': 0x61,
    'get-request': 0xc0,
    'set-request': 0xc1,
    'event-notification-request': 0xc2,
    'action-request': 0xc3,
    'get-response': 0xc4,
    'set-response': 0xc5,
    'event-notification-response': 0xc6,
    'action-response': 0xc7,
    'error': 0xe1
}

HEARTBEAT = {
    'client-id': 0xa1,
    'client-type': 0xa2
}

AUTHORIZATION = {
    'authorisation-value': 0xa3
}

Get_Request = {
    'get-request-normal': 1,
    'get-request-with-list': 2
}

Get_Response = {
    'get-Response-normal': 1,
    'get-response-with-list': 2
}

Set_Request = {
    'set-request-normal': 1,
    'set-request-with-list': 2
}

Set_Response = {
    'set-Response-normal': 1,
    'set-response-with-list': 2
}

Action_Request = {
    'action-request-normal': 1,
    'action-request-with-list': 2
}

Action_Response = {
    'action-Response-normal': 1,
    'action-response-with-list': 2
}

Data_type = {
    'null': 0,
    'array': 1,
    'structure': 2,
    'boolean': 3,
    'string': 4,
    'integer': 5,
    'float': 6
}

Result = {
    'success': 0,
    'object-undefined': 1,
    'other-reason': 2
}


def extractReqData(_clientPacket):
    _packetBytes_count = _clientPacket.__len__()
    # check if recieved bytes less than 2 bytes
    if _packetBytes_count < 2:
        return None, []
    _FLAG = _clientPacket[0]
    # check recieved bytes start and end with _FLAG byte
    if _FLAG != PACKET_FLAG:
        return None, []
    if _clientPacket[_packetBytes_count-1] != _FLAG:
        return None
    # check if number of recieved bytes are corresponding with LENGTH byte
    if _clientPacket[1] != (_packetBytes_count - 5):
        return None, []
    _dataPacket = _clientPacket[3:_packetBytes_count-2]
    # check if CS byte calculated correct
    if (_clientPacket[_packetBytes_count-2] != checksum(_dataPacket)):
        return None, []
    # check if the transmission direction byte is correct
    if _clientPacket[2] != TRANSMISSION_DIRECTION['CtoS']:
        return None, []
    if _dataPacket[0] == APDU['heartbeat']:
        return 'AUTHENTICATION', _dataPacket[1:]
    elif _dataPacket[0] == APDU['aare']:
        return 'AUTHORIZATION', _dataPacket[1:]
    elif _dataPacket[0] == APDU['get-response']:
        return 'GET_RES', _dataPacket[1:]
    elif _dataPacket[0] == APDU['set-response']:
        return 'SET_RES', _dataPacket[1:]
    elif _dataPacket[0] == APDU['action-response']:
        return 'ACT_RES', _dataPacket[1:]
    elif _dataPacket[0] == APDU['event-notification-response']:
        return 'NOTIFICATION', _dataPacket[1:]
    elif _dataPacket[0] == APDU['error']:
        return 'ERROR', _dataPacket[1:]
    else:
        return None, []


def makeMessagePacket(request):
    def request_frame(_input):
        _frame = bytearray()
        _frame.append(PACKET_FLAG)
        _frame.append(0)
        _frame.append(TRANSMISSION_DIRECTION['StoC'])
        _frame += request(_input)
        _frame.append(checksum(_frame[3:_frame.__len__()]))
        _frame.append(PACKET_FLAG)
        _frame[1] = _frame.__len__()-5
        return _frame
    return request_frame


def checksum(_dataPacket):
    _intChecksum = 0
    for _byte in _dataPacket:
        _intChecksum += int(_byte)
    _checksum = _intChecksum.to_bytes(2, 'little')
    return _checksum[0]


@makeMessagePacket
def make_ERROR_message(_errorCode):
    _errorFrame = bytearray()
    _errorFrame.append(APDU['error'])
    _errorFrame += (_errorCode.to_bytes(2, 'big'))
    return _errorFrame


def inspect_AUTHENTICATION_response(_dataFrame):
    clientIdentity = {}
    i = 0
    while i < _dataFrame.__len__():
        if _dataFrame[i] == HEARTBEAT['client-id']:
            clientIdentity['c_id'] = int.from_bytes(_dataFrame[i+1:i+3], 'big')
            i += 3
        elif _dataFrame[i] == HEARTBEAT['client-type']:
            clientIdentity['c_type'] = int(_dataFrame[i+1])
            i += 2
        else:
            break
    return clientIdentity


@makeMessagePacket
def make_AUTHORIZATION_request(_input):
    _reqFrame = bytearray()
    _reqFrame.append(APDU['aarq'])
    _reqFrame.append(AUTHORIZATION['authorisation-value'])
    _reqFrame += (_input ^ SERVER_KEY).to_bytes(2, 'big')
    return _reqFrame


def inspect_AUTHORISATION_response(_dataFrame):
    client_key = -1
    i = 0
    while i < _dataFrame.__len__():
        if _dataFrame[i] == AUTHORIZATION['authorisation-value']:
            client_key = int.from_bytes(_dataFrame[i+1:i+3], 'big')
            i += 3
        else:
            break
    return client_key
