import logging
import dbHelper
import json
from datetime import datetime
import tcpServer
import messageFormation
import queries

CLIENT_KEY = 0x13660813

EXTRA = {'modulename': __name__}


class protocol:
    def __init__(self, _clientAddress):
        self.clientAddress = _clientAddress
        self.client_id = -1
        self.authorized = False
        self.frameCounter = 0x10
        self.lastRequestAttribute = []

    def authenticate(self, _clientFrame):
        _authenticated = False
        _request = []
        # extract HEARBEAT elements from received packet
        clientId = messageFormation.inspect_AUTHENTICATION_response(
            _clientFrame)
        if clientId != -1:
            _authenticated = True
            self.client_id = clientId
            # make AUTHORIZATION-req for client
            _request, self.frameCounter = messageFormation.make_AUTHORIZATION_request(
                self.client_id, self.frameCounter)
            tcpServer.AUTHENTICATED_CLIENTS.append(self.clientAddress)
        logging.info('client %s. identity: %s, address: %s' % (
            ('authenticated' if _authenticated else 'not authenticated'),
            self.int_to_BCDint(self.client_id),
            self.clientAddress),
            extra=EXTRA)
        return _authenticated, _request

    def authorize(self, _clientPacket):
        _request = []
        # extract AUTHORIZATION-res elements from received packet
        clientKey = messageFormation.inspect_AUTHORISATION_response(
            _clientPacket)
        if clientKey != -1:
            if (clientKey ^ messageFormation.SERVER_KEY ^ self.client_id) == CLIENT_KEY:
                tcpServer.AUTHENTICATED_CLIENTS.remove(self.clientAddress)
                tcpServer.AUTHORIZED_CLIENTS.append(
                    (self.clientAddress, self.client_id))
                self.read_dbInfo()
                _db = dbHelper.dbhelper()
                # check existance of authorized gateway
                query = 'select * from %(table)s where %(condition)s = %(condition_val)s'\
                    % {
                        "table": list(self.DBtables.keys())[1],
                        "condition": self.DBtables[list(self.DBtables.keys())[1]]['col_1'],
                        "condition_val": self.int_to_BCDint(self.client_id)
                    }
                # if authorized gateway does not exist before
                if _db.selectData(query) is None:
                    logging.info('new gateway connected, id: %s' %
                                 self.int_to_BCDint(self.client_id),
                                 extra=EXTRA)
                    query = 'insert into %(table)s '\
                        '(%(col_1)s, %(col_2)s, %(col_3)s, %(col_4)s, %(col_5)s) ' \
                        'values (%(val_1)i, %(val_2)i, "%(val_3)s", %(val_4)i, %(val_5)i)' \
                            % {
                                "table": list(self.DBtables.keys())[1],
                                "col_1": self.DBtables[list(self.DBtables.keys())[1]]['col_1'],
                                "val_1": self.int_to_BCDint(self.client_id),
                                "col_2": self.DBtables[list(self.DBtables.keys())[1]]['col_2'],
                                "val_2": True,
                                "col_3": self.DBtables[list(self.DBtables.keys())[1]]['col_3'],
                                "val_3": self.clientAddress,
                                "col_4": self.DBtables[list(self.DBtables.keys())[1]]['col_8'],
                                "val_4": clientKey,
                                "col_5": self.DBtables[list(self.DBtables.keys())[1]]['col_13'],
                                "val_5": datetime.timestamp(datetime.now())
                            }
                    if _db.executeQuery(query):
                        logging.info('new gateway added, id: %s' %
                                     self.int_to_BCDint(self.client_id),
                                     extra=EXTRA)
                    query = queries.ADDITIVE_TABLES['gateway'].replace(
                        '\n', '')
                    query = query.replace('XX', '`%i`' %
                                          self.int_to_BCDint(self.client_id))
                    if _db.executeQuery(query):
                        logging.info("table for logs of new gateway created, id: %s" %
                                     self.int_to_BCDint(self.client_id),
                                     extra=EXTRA)
                    # make GET-req to get more detail of new client
                    self.lastRequestAttribute = [
                        ('abstract', 'device-characteristics', 'sim_no', 1),
                        ('abstract', 'device-characteristics', 'physical-device-info', 1)]
                    _request, self.frameCounter = messageFormation.make_Get_request(
                        self.lastRequestAttribute, self.frameCounter)
                    pass
                # if authorized gateway existed already
                else:
                    query = 'update %(table)s set ' \
                        '%(col_2)s=%(val_2)i, %(col_3)s="%(val_3)s", %(col_4)s=%(val_4)i, %(col_5)s=%(val_5)i ' \
                            'where %(condition)s = %(condition_val)i' \
                        % {
                            "table": list(self.DBtables.keys())[1],
                            "col_2": self.DBtables[list(self.DBtables.keys())[1]]['col_2'],
                            "val_2": True,
                            "col_3": self.DBtables[list(self.DBtables.keys())[1]]['col_3'],
                            "val_3": self.clientAddress,
                            "col_4": self.DBtables[list(self.DBtables.keys())[1]]['col_8'],
                            "val_4": clientKey,
                            "col_5": self.DBtables[list(self.DBtables.keys())[1]]['col_13'],
                            "val_5": datetime.timestamp(datetime.now()),
                            "condition": self.DBtables[list(self.DBtables.keys())[1]]['col_1'],
                            "condition_val": self.int_to_BCDint(self.client_id)
                        }
                    if _db.executeQuery(query):
                        logging.info('gateway information updated, id: %s' %
                                     self.int_to_BCDint(self.client_id),
                                     extra=EXTRA)
                self.authorized = True
                self.log_transition(('CtoS', _clientPacket))
        logging.info('client %s. identity: %s, address: %s' % (
            ('authorized' if self.authorized else 'not authorized'),
            self.int_to_BCDint(self.client_id),
            self.clientAddress),
            extra=EXTRA)
        return self.authorized, _request

    def devoting_to_response(self, _responseType, _clientPacket):
        if self.lastRequestAttribute:
            if _responseType == 'GET-response':
                response_result = messageFormation.inspect_GET_response(
                    _clientPacket)
                if self.lastRequestAttribute.__len__() == response_result.__len__():

                    self.lastRequestAttribute = None
                    pass
            if _responseType == 'SET_response':
                pass
            if _responseType == 'ACTION-response':
                pass
        return

    def read_dbInfo(self):
        try:
            f = open('.env/db_info.json')
            self.DBtables = json.load(f)['main-tables']
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
        _disconnectionReason, self.frameCounter = messageFormation.make_ERROR_message(
            _errorCode, self.frameCounter)
        found_client = [x for x in tcpServer.AUTHORIZED_CLIENTS if x[0]
                        == self.clientAddress]
        if found_client.__len__() > 0:
            # remove client from AUTHORIZED client list and change its activation status to DEACTIVE
            tcpServer.AUTHORIZED_CLIENTS.remove(found_client[0])
            self.read_dbInfo()
            _db = dbHelper.dbhelper()
            query = 'update %(table)s set ' \
                '%(col_2)s=%(val_2)i ' \
                    'where %(condition)s = %(condition_val)i' \
                % {
                    "table": list(self.DBtables.keys())[1],
                    "col_2": self.DBtables[list(self.DBtables.keys())[1]]['col_2'],
                    "val_2": False,
                    "condition": self.DBtables[list(self.DBtables.keys())[1]]['col_1'],
                    "condition_val": self.int_to_BCDint(self.client_id)
                }
            _db.executeQuery(query)
        elif tcpServer.AUTHENTICATED_CLIENTS.__contains__(self.clientAddress):
            tcpServer.AUTHENTICATED_CLIENTS.remove(self.clientAddress)
        logging.warn(
            'client disconnected. reason: %s, address: %s' % (_errorReason, self.clientAddress), extra=EXTRA)
        return _disconnectionReason

    def log_transition(self, log_parameters):
        if self.authorized:
            direction, packet = log_parameters
            _db = dbHelper.dbhelper()
            query = 'insert into `%(table)s` '\
                'values ("%(val_1)s", "%(val_2)s", "%(val_3)s", %(val_4)i)' \
                    % {
                        "table": self.int_to_BCDint(self.client_id),
                        "val_1": self.clientAddress,
                        "val_2": direction,
                        "val_3": packet.hex(),
                        "val_4": datetime.timestamp(datetime.now())
                    }
            if _db.executeQuery(query):
                logging.info('gateway activity logged, id: %s' %
                             self.int_to_BCDint(self.client_id),
                             extra=EXTRA)
