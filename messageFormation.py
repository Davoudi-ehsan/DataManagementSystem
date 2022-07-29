AUTH_FLAG = 0x7e
AUTH_DIRECTION = {'StoC': 0x81, 'CtoS': 0x01}
KEY = 0x1987


def extractAuthData(_clientPacket):
    _validData = []
    _packetBytes_count = _clientPacket.__len__()
    if _packetBytes_count < 2:
        return None
    _FLAG = _clientPacket[0]
    if _FLAG == AUTH_FLAG:
        if _clientPacket[_packetBytes_count-1] != _FLAG:
            return None
        if _clientPacket[1] != (_packetBytes_count - 5):
            return None
        _dataPacket = _clientPacket[3:_packetBytes_count-2]
        if (_clientPacket[_packetBytes_count-2] != checksum(_dataPacket)):
            return None
        if _clientPacket[2] != AUTH_DIRECTION['CtoS']:
            return None
        i = 0
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
                case 0xa3:
                    _validData.append(
                        ('key', int.from_bytes(_dataPacket[i+1:i+3], 'big')))
                    i += 3
                case _:
                    break
    return _validData


def extractReqData(_clientPacket):
    _validData = []
    _packetBytes_count = _clientPacket.__len__()
    if _packetBytes_count < 2:
        return None
    return _validData


def makeResponse(_responseType, _input):
    _response = bytearray()
    match _responseType:
        case 'AUTHENTICATION':
            _response.append(AUTH_FLAG)
            _response.append(3)
            _response.append(AUTH_DIRECTION['StoC'])
            _response.append(0xa3)
            _response += (_input[0] ^ KEY).to_bytes(2, 'big')
            _response.append(checksum(_response[3:6]))
            _response.append(AUTH_FLAG)
        case 'DECLARATION':
            _response.append(AUTH_FLAG)
            _response.append(6)
            _response.append(6)
            _response.append(6)
            _response.append(AUTH_FLAG)
        case 'CORRECT':
            _response.append(AUTH_FLAG)
            _response.append(3)
            _response.append(AUTH_DIRECTION['StoC'])
            _response.append(0xc1)
            _response += (_input.to_bytes(2, 'big'))
            _response.append(checksum(_response[3:6]))
            _response.append(AUTH_FLAG)
        case 'ERROR':
            _response.append(AUTH_FLAG)
            _response.append(3)
            _response.append(AUTH_DIRECTION['StoC'])
            _response.append(0xe1)
            _response += (_input.to_bytes(2, 'big'))
            _response.append(checksum(_response[3:6]))
            _response.append(AUTH_FLAG)
        case 'REQUEST':
            pass
    return _response


def checksum(_dataPacket):
    _intChecksum = 0
    for _byte in _dataPacket:
        _intChecksum += int(_byte)
    _checksum = _intChecksum.to_bytes(2, 'little')
    return _checksum[0]
