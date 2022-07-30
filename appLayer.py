import logging
from tkinter.messagebox import NO
import dbHelper
import json
from datetime import datetime
import tcpServer
import messageFormation

KEY = 0x1987

DIF = {}
VIF = {}


class protocol:
    def __init__(self, _clientAddress):
        self.clientAddress = _clientAddress
        self.c_id = []
        self.c_type = []

    def authenticate(self, _clientPacket):
        self.c_id = [
            value[1] for value in _clientPacket if value[0] == 'c_id']
        self.c_type = [
            value[1] for value in _clientPacket if value[0] == 'c_type']
        if self.c_id.__len__() > 0 and self.c_type.__len__() > 0:
            _authenticated = True
            _response = messageFormation.makeResponse(
                'AUTHENTICATION', self.c_id)
            tcpServer.AUTHENTICATED_CLIENTS.append(self.clientAddress)
            logging.info('client address %s authenticated' %
                         self.clientAddress)
            return _authenticated, _response
        _authenticated = False
        return _authenticated, []

    def authorize(self, _clientPacket):
        key = [
            value[1] for value in _clientPacket if value[0] == 'key']
        if key.__len__() > 0:
            if key[0] == KEY:
                _authorized = True
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
                    query = 'update %(table)s set ' \
                        '%(col_2)s=%(val_2)i, %(col_3)s="%(val_3)s", %(col_4)s="%(val_4)s", %(col_5)s=%(val_5)i ' \
                            'where %(condition)s = %(condition_val)i' \
                        % {
                            "table": self.DBtalbeNames[2],
                            "col_2": self.DBtables[self.DBtalbeNames[2]]['col_2'],
                            "val_2": self.c_type[0],
                            "col_3": self.DBtables[self.DBtalbeNames[2]]['col_3'],
                            "val_3": self.clientAddress,
                            "col_4": self.DBtables[self.DBtalbeNames[2]]['col_4'],
                            "val_4": 'UNKNOWN',
                            "col_5": self.DBtables[self.DBtalbeNames[2]]['col_5'],
                            "val_5": datetime.timestamp(datetime.now()),
                            "condition": self.DBtables[self.DBtalbeNames[2]]['col_1'],
                            "condition_val": self.int_to_BCDint(self.c_id[0])
                        }
                    _request = _db.executeQuery(query)
                    _response = messageFormation.makeResponse('SUCCESS', 202)
                else:
                    _response = messageFormation.makeResponse(
                        'DECLARATION', self.c_type[0])
                logging.info('client address %s authorized' %
                             self.clientAddress)
                return _authorized, _response
        _authorized = False
        return _authorized, []

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
        _disconnectionReason = messageFormation.makeResponse(
            'FAILURE', _errorCode)
        logging.warn(
            'client address %s disconnected duo to %s' % (self.clientAddress, _errorReason))
        return _disconnectionReason
