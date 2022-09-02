import logging
import socketserver
import appLayer
import time
import messageFormation
from pathlib import Path

AUTHORIZED_CLIENTS = []
AUTHENTICATED_CLIENTS = []

BASE_DIR = Path(__file__).resolve().parent
FORMAT = '{ "time": "%(asctime)s", "level": "%(levelname)s", "module": "%(modulename)s", "message": "%(message)s" }'
logging.basicConfig(
    filename=BASE_DIR / 'application_logs.json',
    format=FORMAT,
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')
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
                _reaction = self.appLayer.disconnectClient(
                    204, 'CLIENT_DISCONNECTION')
                break
            logging.info('packet received. %i bytes, address: %s' %
                         (_dataReceived.__len__(), _clientAddress), extra=EXTRA)
            # analyze received packet
            _responseType, _responsePacket = messageFormation.extractReqData(
                _dataReceived, self.appLayer.frameCounter)
            if _responseType is None:
                _reaction = self.appLayer.disconnectClient(
                    406, 'WRONG_RESPONSE')
                self.request.send(_reaction)
                break
            logging.info('packet type: %s, address: %s' %
                         (_clientAddress, _responseType), extra=EXTRA)
            # inspection of content of received packet and making a reaction
            inspection = self.react_to_clientResponse(
                _clientAddress, _responseType, _responsePacket)
            if inspection == 'DISCONNECT_CLIENT':
                break

    def send_serverRequest(self):
        self.request.send(self.serverRequest)
        logging.info(
            "request sent. address: %s" % self.client_address[0], extra=EXTRA)
        self.serverRequest = bytearray()

    def react_to_clientResponse(self, _clientAddress, _responseType, _responsePacket):
        if _responseType == 'AUTHENTICATION':
            # check client for already AUTHORIZATION or AUTHENTICATION
            if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                    AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                _reaction = self.appLayer.disconnectClient(
                    406, 'DUPLICATED_CLIENT')
                self.request.send(_reaction)
                return 'DISCONNECT_CLIENT'
            authenticated, self.serverRequest = self.appLayer.authenticate(
                _responsePacket)
            # check client for c_id duplication and wrong AUTHENTICATION response
            if any(x[1] for x in AUTHORIZED_CLIENTS if x[1] == self.appLayer.c_id) or \
                    not authenticated:
                _reaction = self.appLayer.disconnectClient(
                    400, 'AUTHENTICATION_FAILED')
                self.request.send(_reaction)
                return 'DISCONNECT_CLIENT'
            # self.request.send(AUTHORIZATION_request)
            self.t0 = time.time()
        elif _responseType == 'AUTHORIZATION':
            # check client for already AUTHORIZATION or AUTHENTICATION
            if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                    not AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                _reaction = self.appLayer.disconnectClient(
                    406, 'WRONG_RESPONSE')
                self.request.send(_reaction)
                return 'DISCONNECT_CLIENT'
            # check for timeout
            if (time.time() - self.t0) < 5.01:
                authorized, self.serverRequest = self.appLayer.authorize(
                    _responsePacket)
                # check client for wrong AUTHORIZATION response
                if not authorized:
                    _reaction = self.appLayer.disconnectClient(
                        401, 'AUTHORIZATION_FAILED')
                    self.request.send(_reaction)
                    return 'DISCONNECT_CLIENT'
            else:
                _reaction = self.appLayer.disconnectClient(
                    408, 'AUTHORIZATION_TIMEOUT')
                self.request.send(_reaction)
                return 'DISCONNECT_CLIENT'
        else:
            # if not any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress):
            #     _reaction = self.appLayer.disconnectClient(
            #         406, 'WRONG_RESPONSE')
            #     self.request.send(_reaction)
            #     return 'DISCONNECT_CLIENT'
            _request = self.appLayer.devoting_to_response(
                _responseType, _responsePacket)
            if _request is not None:
                self.request.send(_request)
