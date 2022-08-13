import logging
import socketserver

from pyrsistent import v
import appLayer
import time
import messageFormation

AUTHORIZED_CLIENTS = []
AUTHENTICATED_CLIENTS = []


class SocketServer:
    def __init__(self, _port):
        try:
            self.Server = socketserver.ThreadingTCPServer(
                ('', _port), MyHandler)
        except:
            self.Server = None
            logging.error('tcp server did not create')


class MyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        logging.getLogger().setLevel(logging.INFO)
        _clientAddress = self.client_address[0]
        logging.info('client address %s connected' % _clientAddress)
        self.appLayer = appLayer.protocol(_clientAddress)
        self.serverRequest = bytearray()
        self.t0 = time.time()
        while 1:
            # check if there is any request for client
            if self.serverRequest.__len__() > 0:
                self.send_serverRequest()
            # TODO set timeout for server requests
            # wait for receiption of client packet
            _dataReceived = self.request.recv(1024)
            if not _dataReceived:
                _reaction = self.appLayer.disconnectClient(
                    204, 'CLIENT_DISCONNECTION')
                break
            logging.info('client address %s sent %i bytes' %
                         (_clientAddress, _dataReceived.__len__()))
            # analyze received packet
            _responseType, _responsePacket = messageFormation.extractReqData(
                _dataReceived)
            if _responseType is None:
                _reaction = self.appLayer.disconnectClient(
                    406, 'WRONG_RESPONSE')
                self.request.send(_reaction)
                break
            # inspection of content of received packet and making a reaction
            inspection = self.react_to_clientResponse(
                _clientAddress, _responseType, _responsePacket)
            if inspection == 'DISCONNECT_CLIENT':
                break

    def send_serverRequest(self):
        self.request.send(self.serverRequest)
        logging.info(
            "server's request sent to client address %s" % self.client_address[0])
        self.serverRequest = bytearray()

    def react_to_clientResponse(self, _clientAddress, _responseType, _responsePacket):
        match _responseType:
            case 'AUTHENTICATION':
                # check client for already AUTHORIZATION or AUTHENTICATION
                if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                        AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                    _reaction = self.appLayer.disconnectClient(
                        406, 'WRONG_RESPONSE')
                    self.request.send(_reaction)
                    return 'DISCONNECT_CLIENT'
                authentication_result = self.appLayer.authenticate(
                    _responsePacket)
                # check client for c_id duplication and wrong AUTHENTICATION response
                if any(x[1] for x in AUTHORIZED_CLIENTS if x[1] == self.appLayer.c_id) or \
                        not authentication_result[0]:
                    _reaction = self.appLayer.disconnectClient(
                        400, 'AUTHENTICATION_FAILED')
                    self.request.send(_reaction)
                    return 'DISCONNECT_CLIENT'
                AUTHORIZATION_request = authentication_result[1]
                self.request.send(AUTHORIZATION_request)
                self.t0 = time.time()
            case 'AUTHORIZATION':
                # check client for already AUTHORIZATION or AUTHENTICATION
                if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                        not AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                    _reaction = self.appLayer.disconnectClient(
                        406, 'WRONG_RESPONSE')
                    self.request.send(_reaction)
                    return 'DISCONNECT_CLIENT'
                # check for timeout
                if (time.time() - self.t0) < 5.01:
                    authorization_result = self.appLayer.authorize(
                        _responsePacket)
                    # check client for wrong AUTHORIZATION response
                    if not authorization_result[0]:
                        _reaction = self.appLayer.disconnectClient(
                            401, 'AUTHORIZATION_FAILED')
                        self.request.send(_reaction)
                        return 'DISCONNECT_CLIENT'
                    _request = authorization_result[1]
                    if _request.__len__() > 0:
                        self.request.send(_request)
                else:
                    _reaction = self.appLayer.disconnectClient(
                        408, 'AUTHORIZATION_TIMEOUT')
                    self.request.send(_reaction)
                    return 'DISCONNECT_CLIENT'
            case _:
                if not any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress):
                    _reaction = self.appLayer.disconnectClient(
                        406, 'WRONG_RESPONSE')
                    self.request.send(_reaction)
                    return 'DISCONNECT_CLIENT'
                pass
