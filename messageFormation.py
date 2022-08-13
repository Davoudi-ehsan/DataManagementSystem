import json

SERVER_KEY = 0x1987


def extractReqData(_clientPacket):
    PROTOCOLS = read_protocolInfo('protocols')
    _packetBytes_count = _clientPacket.__len__()
    # check if recieved bytes less than 2 bytes
    if _packetBytes_count < 2:
        return None, []
    _FLAG = _clientPacket[0]
    # check recieved bytes start and end with _FLAG byte
    if _FLAG != int(
            PROTOCOLS['TORAL']['packet-format']['packet-flags']['start']['hex-index'], 16):
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
    if _clientPacket[2] != int(
            PROTOCOLS['TORAL']['packet-format']['transmission-direction']['CtoS']['hex-index'], 16):
        return None, []
    if _dataPacket[0] == int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['HEARTBEAT']['hex-index'], 16):
        return 'AUTHENTICATION', _dataPacket[1:]
    elif _dataPacket[0] == int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['AARE']['hex-index'], 16):
        return 'AUTHORIZATION', _dataPacket[1:]
    elif _dataPacket[0] == int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['GET-response']['hex-index'], 16):
        return 'GET_RES', _dataPacket[1:]
    elif _dataPacket[0] == int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['SET-response']['hex-index'], 16):
        return 'SET_RES', _dataPacket[1:]
    elif _dataPacket[0] == int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['ACTION-response']['hex-index'], 16):
        return 'ACT_RES', _dataPacket[1:]
    elif _dataPacket[0] == int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['EVENT-NOTIFICATION-response']['hex-index'], 16):
        return 'NOTIFICATION', _dataPacket[1:]
    elif _dataPacket[0] == int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['Error']['hex-index'], 16):
        return 'ERROR', _dataPacket[1:]
    else:
        return None, []


def makeMessagePacket(request):
    def request_frame(_input):
        PROTOCOLS = read_protocolInfo('protocols')
        _frame = bytearray()
        _frame.append(int(
            PROTOCOLS['TORAL']['packet-format']['packet-flags']['start']['hex-index'], 16))
        _frame.append(0)
        _frame.append(int(
            PROTOCOLS['TORAL']['packet-format']['transmission-direction']['StoC']['hex-index'], 16))
        _frame += request(_input)
        _frame.append(checksum(_frame[3:_frame.__len__()]))
        _frame.append(int(
            PROTOCOLS['TORAL']['packet-format']['packet-flags']['start']['hex-index'], 16))
        _frame[1] = _frame.__len__()-5
        return _frame
    return request_frame


def read_protocolInfo(_requiredElement):
    f = open('.env/protocol.json')
    return json.load(f)[_requiredElement]


def checksum(_dataPacket):
    _intChecksum = 0
    for _byte in _dataPacket:
        _intChecksum += int(_byte)
    _checksum = _intChecksum.to_bytes(2, 'little')
    return _checksum[0]


@makeMessagePacket
def make_ERROR_message(_errorCode):
    PROTOCOLS = read_protocolInfo('protocols')
    _errorFrame = bytearray()
    _errorFrame.append(int(
        PROTOCOLS['TORAL']['packet-format']['APDU']['Error']['hex-index'], 16))
    _errorFrame += (_errorCode.to_bytes(2, 'big'))
    return _errorFrame


def inspect_AUTHENTICATION_response(_dataFrame):
    PROTOCOLS = read_protocolInfo('protocols')
    clientIdentity = {}
    i = 0
    while i < _dataFrame.__len__():
        if _dataFrame[i] == int(
                PROTOCOLS['TORAL']['packet-format']['APDU']['HEARTBEAT']['elements']['client-id']['hex-index'], 16):
            clientIdentity['c_id'] = int.from_bytes(_dataFrame[i+1:i+3], 'big')
            i += 3
        elif _dataFrame[i] == int(
                PROTOCOLS['TORAL']['packet-format']['APDU']['HEARTBEAT']['elements']['client-type']['hex-index'], 16):
            clientIdentity['c_type'] = int(_dataFrame[i+1])
            i += 2
        else:
            break
    return clientIdentity


@makeMessagePacket
def make_AUTHORIZATION_request(_input):
    PROTOCOLS = read_protocolInfo('protocols')
    _reqFrame = bytearray()
    _reqFrame.append(int(
        PROTOCOLS['TORAL']['packet-format']['APDU']['AARQ']['hex-index'], 16))
    _reqFrame.append(int(
        PROTOCOLS['TORAL']['packet-format']['APDU']['AARQ']['elements']['authorisation-value']['hex-index'], 16))
    _reqFrame += (_input ^ SERVER_KEY).to_bytes(2, 'big')
    return _reqFrame


def inspect_AUTHORISATION_response(_dataFrame):
    PROTOCOLS = read_protocolInfo('protocols')
    client_key = -1
    i = 0
    while i < _dataFrame.__len__():
        if _dataFrame[i] == int(
                PROTOCOLS['TORAL']['packet-format']['APDU']['AARE']['elements']['authorisation-value']['hex-index'], 16):
            client_key = int.from_bytes(_dataFrame[i+1:i+3], 'big')
            i += 3
        else:
            break
    return client_key


@makeMessagePacket
def make_Get_request(_getReqPara):
    PROTOCOLS = read_protocolInfo('protocols')
    OBJECTS = read_protocolInfo('objects')
    _reqItemsLen = _getReqPara.__len__()
    _reqFrame = bytearray()
    if _reqItemsLen == 0:
        return None
    elif _reqItemsLen == 1:
        _obj, _item, _attr = _getReqPara[0]
        _reqFrame.append(int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['GET-request']['hex-index'], 16))
        _reqFrame.append(int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['GET-request']['types']['normal']['index']))
        _reqFrame.append(int(
            OBJECTS[_obj]['A']))
        _reqFrame.append(int(
            OBJECTS[_obj]['items'][_item]['B']))
        _reqFrame.append(_attr)
    else:
        _reqFrame.append(int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['GET-request']['hex-index'], 16))
        _reqFrame.append(int(
            PROTOCOLS['TORAL']['packet-format']['APDU']['GET-request']['types']['with-list']['index']))
        _reqFrame.append(_reqItemsLen)
        for _obj, _item, _attr in _getReqPara:
            _reqFrame.append(int(
                OBJECTS[_obj]['A']))
            _reqFrame.append(int(
                OBJECTS[_obj]['items'][_item]['B']))
            _reqFrame.append(_attr)
    return _reqFrame


def inspect_GET_response(_dataFrame):
    pass
