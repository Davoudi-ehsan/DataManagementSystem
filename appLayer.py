import logging
from tkinter.messagebox import NO
import dbHelper
import json
from datetime import datetime
import tcpServer

AUTH_NAK = 0x15
AUTH_ACK = 0x06
AUTH_FLAG = 0x7e
AUTH_DIRECTION = {'StoC': 0x81, 'CtoS': 0x01}
KEY = 0x1987

DIF = {}
VIF = {}


class protocol:
    def __init__(self, _clientAddress):
        self.clientAddress = _clientAddress
        self.c_id = []
        self.c_type = []

    def authenticate(self, _clientHeartBeat):
        _clientIdentity = self.extractAuthData(_clientHeartBeat)
        self.c_id = [
            value[1] for value in _clientIdentity if value[0] == 'c_id']
        self.c_type = [
            value[1] for value in _clientIdentity if value[0] == 'c_type']
        if self.c_id.__len__() > 0:
            _authenticated = True
            _response = self.makeResponse('AUTHENTICATION', self.c_id)
            tcpServer.AUTHENTICATED_CLIENTS.append(self.clientAddress)
            logging.info('client address %s authenticated' %
                         self.clientAddress)
            return _authenticated, _response
        _authenticated = False
        return _authenticated, []

    def authorize(self, _clientStablishment):
        _clientVerification = self.extractAuthData(_clientStablishment)
        key = [
            value[1] for value in _clientVerification if value[0] == 'key']
        if key.__len__() > 0:
            if key[0] == KEY:
                _authorized = True
                _response = self.makeResponse('CORRECT', 202)
                tcpServer.AUTHENTICATED_CLIENTS.remove(self.clientAddress)
                tcpServer.AUTHORIZED_CLIENTS.append(
                    (self.clientAddress, self.c_id))
                self.read_dbInfo()
                _db = dbHelper.dbhelper()
                query = 'insert into %(table)s ' \
                    'values (%(val_1)i, %(val_2)i, "%(val_3)s", %(val_4)d, %(val_5)i)' \
                        % {
                            "table": self.DBtalbeNames[3],
                            "val_1": self.int_to_BCDint(self.c_id[0]),
                            "val_2": self.c_type[0],
                            "val_3": self.clientAddress,
                            "val_4": 1,
                            "val_5": datetime.timestamp(datetime.now())
                        }
                _request = _db.executeQuery(query)
                query = 'select * from %(table)s where %(condition)s = %(condition_val)i' \
                    % {
                        "table": self.DBtalbeNames[2],
                        "condition": self.DBtables[self.DBtalbeNames[2]]['col_1'],
                        "condition_val": self.int_to_BCDint(self.c_id[0])
                    }
                if _db.selectData(query) is not None:
                    query = 'delete from %(table)s where %(condition)s = %(condition_val)i' \
                        % {
                            "table": self.DBtalbeNames[2],
                            "condition": self.DBtables[self.DBtalbeNames[2]]['col_1'],
                            "condition_val": self.int_to_BCDint(self.c_id[0])
                        }
                    _request = _db.executeQuery(query)
                query = 'insert into %(table)s ' \
                    'values (%(val_1)i, %(val_2)i, "%(val_3)s", "%(val_4)s", %(val_5)i)' \
                        % {
                            "table": self.DBtalbeNames[2],
                            "val_1": self.int_to_BCDint(self.c_id[0]),
                            "val_2": self.c_type[0],
                            "val_3": self.clientAddress,
                            "val_4": 'UNKNOWN',
                            "val_5": datetime.timestamp(datetime.now())
                        }
                _request = _db.executeQuery(query)
                logging.info('client address %s authorized' %
                             self.clientAddress)
                return _authorized, _response
        _authorized = False
        return _authorized, []

    def extractAuthData(self, _clientPacket):
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
            if (_clientPacket[_packetBytes_count-2] != self.checksum(_dataPacket)):
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

    def extractReqData(self, _clientPacket):
        _validData = []
        _packetBytes_count = _clientPacket.__len__()
        if _packetBytes_count < 2:
            return None
        return _validData

    def makeResponse(self, _responseType, _input):
        _response = bytearray()
        match _responseType:
            case 'AUTHENTICATION':
                _response.append(AUTH_FLAG)
                _response.append(3)
                _response.append(AUTH_DIRECTION['StoC'])
                _response.append(0xa3)
                _response += (_input[0] ^ KEY).to_bytes(2, 'big')
                _response.append(self.checksum(_response[3:6]))
                _response.append(AUTH_FLAG)
            case 'CORRECT':
                _response.append(AUTH_FLAG)
                _response.append(3)
                _response.append(AUTH_DIRECTION['StoC'])
                _response.append(0xc1)
                _response += (_input.to_bytes(2, 'big'))
                _response.append(self.checksum(_response[3:6]))
                _response.append(AUTH_FLAG)
            case 'ERROR':
                _response.append(AUTH_FLAG)
                _response.append(3)
                _response.append(AUTH_DIRECTION['StoC'])
                _response.append(0xe1)
                _response += (_input.to_bytes(2, 'big'))
                _response.append(self.checksum(_response[3:6]))
                _response.append(AUTH_FLAG)
            case 'REQUEST':
                pass
        return _response

    def checksum(self, _dataPacket):
        _intChecksum = 0
        for _byte in _dataPacket:
            _intChecksum += int(_byte)
        _checksum = _intChecksum.to_bytes(2, 'little')
        return _checksum[0]

    def read_dbInfo(self):
        f = open('.env/db_info.json')
        self.DBtables = json.load(f)['tables']
        self.DBtalbeNames = list(self.DBtables)

    def int_to_BCDint(self, _value):
        _output = ''
        while _value != 0:
            _output += str(_value % 16)
            _value = _value // 16
        return int(_output[::-1])

    # def BCDint_to_int(self, _value):
    #     _sum = 0
    #     digits = len(str(_value))
    #     for chr in str(_value)[::-1]:
    #         power = int(str(_value)[::-1].index(chr))
    #         _sum += int(chr) * 16 ^ power
    #     return _sum

    def disconnectClient(self, _errorCode, _errorReason):
        found_client = [x for x in tcpServer.AUTHORIZED_CLIENTS if x[0]
                        == self.clientAddress]
        if found_client.__len__() > 0:
            tcpServer.AUTHORIZED_CLIENTS.remove(found_client[0])
            self.read_dbInfo()
            query = 'update %(table)s set %(column)s = %(value)d where %(condition)s = "%(condition_val)s"' \
                % {
                    "table": self.DBtalbeNames[3],
                    "column": self.DBtables[self.DBtalbeNames[3]]['col_4'],
                    "value": 0,
                    "condition": self.DBtables[self.DBtalbeNames[3]]['col_3'],
                    "condition_val": self.clientAddress
                }
            _db = dbHelper.dbhelper()
            _request = _db.executeQuery(query)
        elif tcpServer.AUTHENTICATED_CLIENTS.__contains__(self.clientAddress):
            tcpServer.AUTHENTICATED_CLIENTS.remove(self.clientAddress)
        _disconnectionReason = self.makeResponse('ERROR', _errorCode)
        logging.warn(
            'client address %s disconnected duo to %s' % (self.clientAddress, _errorReason))
        return _disconnectionReason
