import json
import logging

SERVER_KEY = 0x19871104

EXTRA = {'modulename': __name__}


def extractReqData(_clientPacket, _frameCounter):
    PROTOCOL = read_protocolInfo(['protocol', 'TORAL', 'packet-format'])
    _packetBytes_count = _clientPacket.__len__()
    # check if recieved bytes less than 10 bytes
    if _packetBytes_count < 8:
        return None, []
    _FLAG = _clientPacket[0]
    # check recieved bytes start and end with _FLAG byte
    if _FLAG != int(
            PROTOCOL['packet-flag']['start']['hex-index'], 16):
        return None, []
    if _clientPacket[-1] != _FLAG:
        return None
    # check if number of recieved bytes are corresponding with LENGTH byte
    if _clientPacket[1] != (_packetBytes_count - 5):
        return None, []
    _dataPacket = _clientPacket[2:_packetBytes_count-2]
    # check if CS byte calculated correct
    if (_clientPacket[-2] != checksum(_dataPacket)):
        return None, []
    # check if the frame counter byte is correct
    if _clientPacket[2] != _frameCounter + 32:
        return None, []
    # determine response type from identification byte
    if _dataPacket[1] == int(
            PROTOCOL['APDU']['HEARTBEAT']['hex-index'], 16):
        return 'AUTHENTICATION', _dataPacket[2:]
    elif _dataPacket[1] == int(
            PROTOCOL['APDU']['AARE']['hex-index'], 16):
        return 'AUTHORIZATION', _dataPacket[2:]
    elif _dataPacket[1] == int(
            PROTOCOL['APDU']['GET-response']['hex-index'], 16):
        return 'GET-response', _dataPacket[2:]
    elif _dataPacket[1] == int(
            PROTOCOL['APDU']['SET-response']['hex-index'], 16):
        return 'SET-response', _dataPacket[2:]
    elif _dataPacket[1] == int(
            PROTOCOL['APDU']['ACTION-response']['hex-index'], 16):
        return 'ACTION-response', _dataPacket[2:]
    elif _dataPacket[1] == int(
            PROTOCOL['APDU']['EVENT-NOTIFICATION-response']['hex-index'], 16):
        return 'EVENT-NOTIFICATION-response', _dataPacket[2:]
    else:
        return None, []


def read_protocolInfo(_requiredElement):
    try:
        f = open('.env/protocol.json')
        _output = json.load(f)
        for item in _requiredElement:
            _output = _output[item]
        return _output
    except Exception:
        logging.error('reading json file failed', extra=EXTRA)
        return None


def checksum(_dataPacket):
    _intChecksum = 0
    for _byte in _dataPacket:
        _intChecksum += int(_byte)
    _checksum = _intChecksum.to_bytes(2, 'little')
    return _checksum[0]


def attribute_descriptor_to_bytes(_attributeDescriptor):
    _output = bytearray()
    ATTRIBUTE = read_protocolInfo(['attribute-descriptor'])
    _device, _category, _object, _attribute = _attributeDescriptor
    if ATTRIBUTE:
        _output.append(int(
            ATTRIBUTE[_device]['A']))
        _output.append(int(
            ATTRIBUTE[_device]['category'][_category]['B']))
        _output.append(int(
            ATTRIBUTE[_device]['category'][_category]['object'][_object]['C']))
        _output.append(_attribute)
    return _output


def makeMessagePacket(request):
    def request_frame(_input, _frameCounter):
        _frame = bytearray()
        PROTOCOL = read_protocolInfo(['protocol', 'TORAL', 'packet-format'])
        if PROTOCOL:
            _frame.append(int(
                PROTOCOL['packet-flag']['start']['hex-index'], 16))
            _frame.append(0)
            if _frameCounter < 0xdc:
                _frameCounter += 34
            else:
                _frameCounter = 0x10
            _frame.append(_frameCounter)
            _frame += request(_input, _frameCounter)
            _frame.append(checksum(_frame[2:_frame.__len__()]))
            _frame.append(int(
                PROTOCOL['packet-flag']['start']['hex-index'], 16))
            _frame[1] = _frame.__len__()-5
        return _frame, _frameCounter
    return request_frame


@makeMessagePacket
def make_ERROR_message(_errorCode, _frameCounter):
    _errorFrame = bytearray()
    PROTOCOL = read_protocolInfo(
        ['protocol', 'TORAL', 'packet-format', 'APDU'])
    if PROTOCOL is not None:
        _errorFrame.append(int(
            PROTOCOL['ERROR']['hex-index'], 16))
        _errorFrame += (_errorCode.to_bytes(2, 'big'))
    return _errorFrame


def inspect_AUTHENTICATION_response(_dataFrame):
    clientId = -1
    PROTOCOL = read_protocolInfo(
        ['protocol', 'TORAL', 'packet-format', 'APDU', 'HEARTBEAT', 'element'])
    if PROTOCOL:
        if _dataFrame.__len__() == 5:
            if _dataFrame[0] == int(
                    PROTOCOL['client-id']['hex-index'], 16):
                if _dataFrame[1:].__len__() == 4:
                    clientId = int.from_bytes(
                        _dataFrame[1:], 'big')
    return clientId


@makeMessagePacket
def make_AUTHORIZATION_request(_input, _frameCounter):
    _reqFrame = bytearray()
    PROTOCOL = read_protocolInfo(
        ['protocol', 'TORAL', 'packet-format', 'APDU', 'AARQ'])
    if PROTOCOL:
        _reqFrame.append(int(
            PROTOCOL['hex-index'], 16))
        _reqFrame.append(int(
            PROTOCOL['element']['authorisation-value']['hex-index'], 16))
        _reqFrame += (_input ^ SERVER_KEY).to_bytes(4, 'big')
    return _reqFrame


def inspect_AUTHORISATION_response(_dataFrame):
    client_key = -1
    PROTOCOL = read_protocolInfo(
        ['protocol', 'TORAL', 'packet-format', 'APDU'])
    if PROTOCOL:
        if _dataFrame.__len__() == 5:
            if _dataFrame[0] == int(
                    PROTOCOL['AARE']['element']['authorisation-value']['hex-index'], 16):
                client_key = int.from_bytes(_dataFrame[1:], 'big')
    return client_key


@makeMessagePacket
def make_Get_request(_getReqPara, _frameCounter):
    _reqFrame = bytearray()
    PROTOCOL = read_protocolInfo(
        ['protocol', 'TORAL', 'packet-format', 'APDU', 'GET-request'])
    if PROTOCOL:
        _reqItemsLen = _getReqPara.__len__()
        _reqFrame.append(int(
            PROTOCOL['hex-index'], 16))
        if _reqItemsLen == 0:
            return None
        elif _reqItemsLen == 1:
            _reqFrame.append(int(
                PROTOCOL['type']['normal']['index']))
            _reqFrame += attribute_descriptor_to_bytes(_getReqPara[0])
        else:
            _reqFrame.append(int(
                PROTOCOL['type']['with-list']['index']))
            _reqFrame.append(_reqItemsLen)
            for _attributeDescriptor in _getReqPara:
                _reqFrame += attribute_descriptor_to_bytes(
                    _attributeDescriptor)
    return _reqFrame


def inspect_GET_response(_dataFrame: bytes):
    PROTOCOL = read_protocolInfo(
        ['protocol', 'TORAL', 'packet-format', 'APDU', 'GET-response', 'type'])
    # _category = [list(OBJECTS.keys())[list(OBJECTS.values()).index(i)]
    #              for i in OBJECTS.values() if i['A'] == _dataFrame[2]]
    # _item = [list(OBJECTS[_category[0]]['items'].keys())
    #          [list(OBJECTS[_category[0]]['items'].values()).index(i)]
    #          for i in OBJECTS[_category[0]]['items'].values() if i['B'] == _dataFrame[3]]
    # print(_category[0], _item[0])
    if PROTOCOL:
        if _dataFrame[0] == int(PROTOCOL['normal']['index']):
            return extract_dataResult(_dataFrame[1:], 'normal')
        elif _dataFrame[0] == int(PROTOCOL['with-list']['index']):
            return extract_dataResult(_dataFrame[1:], 'with-list')
    return None


def extract_dataResult(_rawData: bytes, _responseType: str):
    _outputData = []
    DATA_RESULT = read_protocolInfo(['data-result'])
    if DATA_RESULT:
        if _responseType == 'normal':
            if _rawData[0] == int(DATA_RESULT['data']['index']):
                _rawData, result = trim_dataByteArray(_rawData[1:])
                _outputData.append(result)
            elif _rawData[0] == int(DATA_RESULT['data-access-result']['index']):
                result = list(DATA_RESULT['data-access-result']['result'].keys())[
                    list(DATA_RESULT['data-access-result']['result'].values()).index(_rawData[1])]
                _outputData.append(result)
        elif _responseType == 'with-list':
            resultItemsNumber = _rawData[0]
            _rawData = _rawData[1:]
            for i in range(resultItemsNumber):
                if _rawData.__len__() > 1:
                    if _rawData[0] == int(DATA_RESULT['data']['index']):
                        _rawData, result = trim_dataByteArray(_rawData[1:])
                        _outputData.append(result)
                    elif _rawData[0] == int(DATA_RESULT['data-access-result']['index']):
                        result = list(DATA_RESULT['data-access-result']['result'].keys())[
                            list(DATA_RESULT['data-access-result']['result'].values()).index(_rawData[1])]
                        _outputData.append(result)
                        _rawData = _rawData[2:]
                    else:
                        break
                else:
                    break
    return _outputData


def trim_dataByteArray(_byteArray: bytes):
    _resultItem: object = None
    DATA_TYPE = read_protocolInfo(['data-type'])
    if DATA_TYPE:
        if _byteArray[0] in list(DATA_TYPE.values()):
            if _byteArray[0] == DATA_TYPE['array']:
                _byteArray, _resultItem = get_arrayElements(_byteArray[1:])
            elif _byteArray[0] == DATA_TYPE['structure']:
                _byteArray, _resultItem = get_structureElements(_byteArray)
            else:
                _byteArray, _resultItem = get_singelElement(_byteArray)
    return _byteArray, _resultItem


def get_arrayElements(_data: bytes):
    _dataItems = []
    _byteArray = []
    DATA_TYPE = read_protocolInfo(['data-type'])
    if DATA_TYPE:
        if _data.__len__() < 3:
            return [], []
        if not _data[1] == DATA_TYPE['structure']:
            return [], []
        arrayLENGTH = _data[0]
        _byteArray = _data[1:]
        for i in range(arrayLENGTH):
            _byteArray, _resultItem = get_structureElements(_byteArray)
            _dataItems.append(_resultItem)
    return _byteArray, _dataItems


def get_structureElements(_data: bytes):
    _dataItems = []
    if _data.__len__() < 3:
        return [], []
    structureItems = _data[1]
    _byteArray = _data[2:]
    for i in range(structureItems):
        _byteArray, _resultItem = get_singelElement(_byteArray)
        _dataItems.append(_resultItem)
    return _byteArray, _dataItems


def get_singelElement(_data: bytes):
    _elementValue: object = None
    _byteArray = []
    DATA_TYPE = read_protocolInfo(['data-type'])
    if DATA_TYPE:
        if _data[0] == DATA_TYPE['null']:
            _elementValue = 'null'
            _byteArray = _data[1:] if _data.__len__() > 1 else []
        elif _data[0] == DATA_TYPE['boolean'] and _data.__len__() > 1:
            _elementValue = True if _data[1] else False
            _byteArray = _data[2:] if _data.__len__() > 2 else []
        elif _data[0] == DATA_TYPE['unsigned32'] and _data.__len__() > 4:
            _elementValue = int.from_bytes(_data[1:5], 'big')
            _byteArray = _data[5:] if _data.__len__() > 5 else []
        elif _data[0] == DATA_TYPE['octet-string'] and _data.__len__() > 2:
            if _data[1] < _data.__len__() - 1:
                _elementValue = ''
                for i in range(2, 2 + _data[1]):
                    _elementValue += '%02d' % _data[i]
                _byteArray = _data[2+_data[1]:]
        elif _data[0] == DATA_TYPE['visual-string'] and _data.__len__() > 2:
            if _data[1] < _data.__len__() - 1:
                _elementValue = _data[2:2+_data[1]].decode('utf-8')
                _byteArray = _data[2+_data[1]:]
        elif _data[0] == DATA_TYPE['unsigned16'] and _data.__len__() > 2:
            _elementValue = int.from_bytes(_data[1:3], 'big')
            _byteArray = _data[3:] if _data.__len__() > 3 else []
        elif _data[0] == DATA_TYPE['unsigned'] and _data.__len__() > 1:
            _elementValue = _data[1]
            _byteArray = _data[2:] if _data.__len__() > 2 else []
    return _byteArray, _elementValue
