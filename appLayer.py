import logging
import dbHelper
import json
from datetime import datetime
import tcpServer
import messageFormation

CLIENT_KEY = 0x1987

EXTRA = {'modulename': __name__}


class protocol:
    def __init__(self, _clientAddress):
        self.clientAddress = _clientAddress
        self.c_id = -1
        self.c_type = -1
        self.frameCounter = 0x10
        self.lastRequestAttribute = []

    def authenticate(self, _clientFrame):
        _authenticated = False
        _request = []
        # extract HEARBEAT elements from received packet
        clientIdentity = messageFormation.inspect_AUTHENTICATION_response(
            _clientFrame)
        if 'c_id' in clientIdentity and 'c_type' in clientIdentity:
            _authenticated = True
            self.c_id = clientIdentity['c_id']
            self.c_type = clientIdentity['c_type']
            # make AUTHORIZATION-req for client
            _request, self.frameCounter = messageFormation.make_AUTHORIZATION_request(
                self.c_id, self.frameCounter)
            tcpServer.AUTHENTICATED_CLIENTS.append(self.clientAddress)
        logging.info('client %s. address: %s, identity: %s' % (
            ('authenticated' if _authenticated else 'not authenticated'),
            self.clientAddress,
            clientIdentity),
            extra=EXTRA)
        return _authenticated, _request

    def authorize(self, _clientPacket):
        _authorized = False
        _request = []
        # extract AUTHORIZATION-res elements from received packet
        clientKey = messageFormation.inspect_AUTHORISATION_response(
            _clientPacket)
        if clientKey != -1:
            if clientKey == CLIENT_KEY:
                tcpServer.AUTHENTICATED_CLIENTS.remove(self.clientAddress)
                tcpServer.AUTHORIZED_CLIENTS.append(
                    (self.clientAddress, self.c_id))
                self.read_dbInfo()
                _db = dbHelper.dbhelper()
                # add new connection to connection log table
                query = 'insert into %(table)s ' \
                    'values (%(val_1)i, %(val_2)i, "%(val_3)s", %(val_4)d, %(val_5)i)' \
                        % {
                            "table": self.DBtalbeNames[3],
                            "val_1": self.int_to_BCDint(self.c_id),
                            "val_2": self.c_type,
                            "val_3": self.clientAddress,
                            "val_4": 1,
                            "val_5": datetime.timestamp(datetime.now())
                        }
                _result = _db.executeQuery(query)
                logging.info('connection logged, address: %s' %
                             self.clientAddress,
                             extra=EXTRA)
                # check regitered device table for client existance
                query = 'select * from %(table)s where %(condition)s = %(condition_val)i' \
                    % {
                        "table": self.DBtalbeNames[2],
                        "condition": self.DBtables[self.DBtalbeNames[2]]['col_1'],
                        "condition_val": self.int_to_BCDint(self.c_id)
                    }
                if _db.selectData(query) is not None:
                    # update information of device in registered table
                    query = 'update %(table)s set ' \
                        '%(col_2)s=%(val_2)i, %(col_3)s="%(val_3)s", %(col_4)s="%(val_4)s", %(col_5)s=%(val_5)i ' \
                            'where %(condition)s = %(condition_val)i' \
                        % {
                            "table": self.DBtalbeNames[2],
                            "col_2": self.DBtables[self.DBtalbeNames[2]]['col_2'],
                            "val_2": self.c_type,
                            "col_3": self.DBtables[self.DBtalbeNames[2]]['col_3'],
                            "val_3": self.clientAddress,
                            "col_4": self.DBtables[self.DBtalbeNames[2]]['col_4'],
                            "val_4": 'UNKNOWN',
                            "col_5": self.DBtables[self.DBtalbeNames[2]]['col_5'],
                            "val_5": datetime.timestamp(datetime.now()),
                            "condition": self.DBtables[self.DBtalbeNames[2]]['col_1'],
                            "condition_val": self.int_to_BCDint(self.c_id)
                        }
                    _result = _db.executeQuery(query)
                    logging.info('client information updated, address: %s' %
                                 self.clientAddress,
                                 extra=EXTRA)
                else:
                    # add information of new device in registered table
                    query = 'insert into %(table)s ' \
                        'values (%(val_1)i, %(val_2)i, "%(val_3)s", %(val_4)d, %(val_5)i)' \
                            % {
                                "table": self.DBtalbeNames[2],
                                "val_1": self.int_to_BCDint(self.c_id),
                                "val_2": self.c_type,
                                "val_3": self.clientAddress,
                                "val_4": 'UNKNOWN',
                                "val_5": datetime.timestamp(datetime.now())
                            }
                    _result = _db.executeQuery(query)
                    logging.info('client registered, address: %s' %
                                 self.clientAddress,
                                 extra=EXTRA)
                    # make GET-req to get more detail of new client
                    self.lastRequestAttribute = [
                        ('abstract', 'configuration', 'local-connected-downstream-devices', 1)]
                    _request, self.frameCounter = messageFormation.make_Get_request(
                        self.lastRequestAttribute, self.frameCounter)
                _authorized = True
        logging.info('client %s. address: %s' % (
            ('authorized' if _authorized else 'not authorized'),
            self.clientAddress),
            extra=EXTRA)
        return _authorized, _request

    def devoting_to_response(self, _responseType, _clientPacket):
        if _responseType == 'GET-response':
            response_result = messageFormation.inspect_GET_response(
                _clientPacket)
            pass
        if _responseType == 'SET_response':
            pass
        if _responseType == 'ACTION-response':
            pass
        if _responseType == 'EVENT-NOTIFICATION-response':
            pass
        return

    def read_dbInfo(self):
        try:
            f = open('.env/db_info.json')
            self.DBtables = json.load(f)['tables']
            self.DBtalbeNames = list(self.DBtables)
        except Exception:
            logging.error('reading json file failed', extra=EXTRA)

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
            # remove client from AUTHORIZED client list and change its activation status to DEACTIVE
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
            logging.info('disconnection logged, address: %s' %
                         self.clientAddress,
                         extra=EXTRA)
        elif tcpServer.AUTHENTICATED_CLIENTS.__contains__(self.clientAddress):
            tcpServer.AUTHENTICATED_CLIENTS.remove(self.clientAddress)
        _disconnectionReason, self.frameCounter = messageFormation.make_ERROR_message(
            _errorCode, self.frameCounter)
        logging.warn(
            'client disconnected. address: %s, reason: %s' % (self.clientAddress, _errorReason), extra=EXTRA)
        return _disconnectionReason
