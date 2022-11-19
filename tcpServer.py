import logging
import socketserver
import appLayer
import time
import messageFormation

AUTHORIZED_CLIENTS = []
AUTHENTICATED_CLIENTS = []

EXTRA = {'modulename': __name__}


class SocketServer:
    def __init__(self, _port):
        try:
            self.Server = socketserver.ThreadingTCPServer(
                ('', _port), MyHandler)
            logging.info('TCP Server created on port: %i' % _port, extra=EXTRA)
        except:
            self.Server = None
            logging.error('TCP Server did not create', extra=EXTRA)


class MyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        _clientAddress = self.client_address[0]
        logging.info('client connected! address: %s' %
                     _clientAddress, extra=EXTRA)
        # make an instance of protocol for new client
        self.appLayer = appLayer.protocol(_clientAddress)
        self.serverRequest = bytearray()
        self.t0 = time.time()
        while 1:
            # check if there is any request for client
            if self.serverRequest.__len__() > 0:
                logging.info('request is available! address: %s' %
                             _clientAddress, extra=EXTRA)
                self.send_serverRequest()
            # TODO set timeout for server requests
            # wait for receiption of client packet
            _dataReceived = self.request.recv(1024)
            if not _dataReceived:
                self.appLayer.disconnectClient(
                    204, 'CLIENT_DISCONNECTION')
                break
            logging.info('packet received. %i bytes, address: %s' %
                         (_dataReceived.__len__(), _clientAddress), extra=EXTRA)
            self.appLayer.log_transition(('CtoS', _dataReceived))
            # analyze received packet
            _responseType, _responsePacket = messageFormation.extractReqData(
                _dataReceived, self.appLayer.frameCounter)
            if _responseType is None:
                self.serverRequest = self.appLayer.disconnectClient(
                    406, 'WRONG_RESPONSE')
                self.send_serverRequest()
                break
            logging.info('received packet type: %s, address: %s' %
                         (_responseType, _clientAddress), extra=EXTRA)
            # inspection of content of received packet and making a reaction
            inspection = self.react_to_clientResponse(
                _clientAddress, _responseType, _responsePacket)
            if inspection == 'DISCONNECT_CLIENT':
                self.send_serverRequest()
                break

    def send_serverRequest(self):
        try:
            self.request.send(self.serverRequest)
            logging.info(
                "request sent. address: %s" % self.client_address[0], extra=EXTRA)
            self.appLayer.log_transition(('StoC', self.serverRequest))
            self.serverRequest = bytearray()
            self.t0 = time.time()
        except Exception as e:
            logging.error('sending request failed', extra=EXTRA, exc_info=e)

    def react_to_clientResponse(self, _clientAddress, _responseType, _responsePacket):
        if _responseType == 'AUTHENTICATION':
            # check client for already AUTHORIZATION or AUTHENTICATION
            if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                    AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                self.serverRequest = self.appLayer.disconnectClient(
                    406, 'DUPLICATED_CLIENT')
                return 'DISCONNECT_CLIENT'
            authenticated, self.serverRequest = self.appLayer.authenticate(
                _responsePacket)
            # check client for client_id duplication and wrong AUTHENTICATION response
            if any(x[1] for x in AUTHORIZED_CLIENTS if x[1] == self.appLayer.client_id) or \
                    not authenticated:
                self.serverRequest = self.appLayer.disconnectClient(
                    400, 'AUTHENTICATION_FAILED')
                return 'DISCONNECT_CLIENT'
            # self.request.send(AUTHORIZATION_request)
        elif _responseType == 'AUTHORIZATION':
            # check client for already AUTHORIZATION or AUTHENTICATION
            if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                    not AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                self.serverRequest = self.appLayer.disconnectClient(
                    406, 'WRONG_RESPONSE')
                return 'DISCONNECT_CLIENT'
            # check for timeout
            if (time.time() - self.t0) < 5.01:
                authorized, self.serverRequest = self.appLayer.authorize(
                    _responsePacket)
                # check client for wrong AUTHORIZATION response
                if not authorized:
                    self.serverRequest = self.appLayer.disconnectClient(
                        401, 'AUTHORIZATION_FAILED')
                    return 'DISCONNECT_CLIENT'
            else:
                self.serverRequest = self.appLayer.disconnectClient(
                    408, 'AUTHORIZATION_TIMEOUT')
                return 'DISCONNECT_CLIENT'
        else:
            if not any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress):
                self.serverRequest = self.appLayer.disconnectClient(
                    406, 'WRONG_RESPONSE')
                return 'DISCONNECT_CLIENT'
            if _responseType == 'EVENT-NOTIFICATION-response':
                pass
            else:
                self.appLayer.devoting_to_response(
                    _responseType, _responsePacket)
