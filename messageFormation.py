

PACKET_FLAG = 0x7e
HEARTBEAT_IDENTIFIER = 0xDD
AARQ_IDENTIFIER = 0x60
AARE_IDENTIFIER = 0x61
GETRQ_IDENTIFIER = 0xc0
GETRE_IDENTIFIER = 0xc4
SETRQ_IDENTIFIER = 0xc1
SETRE_IDENTIFIER = 0xc5
ACTRQ_IDENTIFIER = 0xc2
ACTRE_IDENTIFIER = 0xc6
NOTRE_IDENTIFIER = 0xc7
AUTH_DIRECTION = {'StoC': 0x81, 'CtoS': 0x01}
KEY = 0x1987


def extractReqData(_clientPacket):
    _validData = []
    _packetBytes_count = _clientPacket.__len__()
    # check if recieved bytes less than 2 bytes
    if _packetBytes_count < 2:
        return _validData
    _FLAG = _clientPacket[0]
    # check recieved bytes start and end with _FLAG byte
    if _FLAG != PACKET_FLAG:
        return _validData
    if _clientPacket[_packetBytes_count-1] != _FLAG:
        return _validData
    # check if number of recieved bytes are corresponding with LENGTH byte
    if _clientPacket[1] != (_packetBytes_count - 5):
        return _validData
    _dataPacket = _clientPacket[3:_packetBytes_count-2]
    # check if CS byte calculated correct
    if (_clientPacket[_packetBytes_count-2] != checksum(_dataPacket)):
        return _validData
    # check if the transmission direction byte is correct
    if _clientPacket[2] != AUTH_DIRECTION['CtoS']:
        return _validData
    i = 1
    if _dataPacket[0] == HEARTBEAT_IDENTIFIER:
        _validData.append(('req_type', 'AUTHENTICATION'))
        while i < _dataPacket.__len__():
            match _dataPacket[i]:
                case 0xa1:
                    _validData.append(
                        ('c_id', int.from_bytes(_dataPacket[i+1:i+3], 'big')))
                    i += 3
                case 0xa2:
                    _validData.append(
                        ('c_type', int(_dataPacket[i+1])))
                    i += 2
                case _:
                    break
    elif _dataPacket[0] == AARE_IDENTIFIER:
        _validData.append(('req_type', 'AUTHORIZATION'))
        while i < _dataPacket.__len__():
            match _dataPacket[i]:
                case 0xa3:
                    _validData.append(
                        ('key', int.from_bytes(_dataPacket[i+1:i+3], 'big')))
                    i += 3
                case _:
                    break
    elif _dataPacket[0] == GETRE_IDENTIFIER:
        pass
    elif _dataPacket[0] == SETRE_IDENTIFIER:
        pass
    elif _dataPacket[0] == ACTRE_IDENTIFIER:
        pass
    elif _dataPacket[0] == NOTRE_IDENTIFIER:
        pass
    return _validData


def makeResponse(_responseType, _input):
    _response = bytearray()
    match _responseType:
        case 'AUTHENTICATION':
            _response.append(PACKET_FLAG)
            _response.append(0)
            _response.append(AUTH_DIRECTION['StoC'])
            _response.append(AARQ_IDENTIFIER)
            _response.append(0xa3)
            _response += (_input[0] ^ KEY).to_bytes(2, 'big')
            _response.append(checksum(_response[3:_response.__len__()]))
            _response.append(PACKET_FLAG)
            _response[1] = _response.__len__()-5
        case 'DECLARATION':
            _response.append(PACKET_FLAG)
            _response.append(0)
            _response.append(AUTH_DIRECTION['StoC'])

            _response.append(checksum(_response[3:_response.__len__()]))
            _response.append(PACKET_FLAG)
            _response[1] = _response.__len__()-5
        case 'SUCCESS':
            _response.append(PACKET_FLAG)
            _response.append(0)
            _response.append(AUTH_DIRECTION['StoC'])
            _response.append(AARQ_IDENTIFIER)
            _response.append(0xc1)
            _response += (_input.to_bytes(2, 'big'))
            _response.append(checksum(_response[3:_response.__len__()]))
            _response.append(PACKET_FLAG)
            _response[1] = _response.__len__()-5
        case 'FAILURE':
            _response.append(PACKET_FLAG)
            _response.append(0)
            _response.append(AUTH_DIRECTION['StoC'])
            _response.append(AARQ_IDENTIFIER)
            _response.append(0xe1)
            _response += (_input.to_bytes(2, 'big'))
            _response.append(checksum(_response[3:_response.__len__()]))
            _response.append(PACKET_FLAG)
            _response[1] = _response.__len__()-5
        case 'REQUEST':
            pass
    return _response


def checksum(_dataPacket):
    _intChecksum = 0
    for _byte in _dataPacket:
        _intChecksum += int(_byte)
    _checksum = _intChecksum.to_bytes(2, 'little')
    return _checksum[0]
