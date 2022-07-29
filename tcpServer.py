import logging
import socketserver
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
        t0 = time.time()
        while 1:
            if self.serverRequest.__len__() > 0:
                self.request.send(self.serverRequest)
                logging.info(
                    "server's request sent to client address %s" % _clientAddress)
                self.serverRequest = bytearray()
            _dataReceived = self.request.recv(1024)
            if not _dataReceived:
                _response = self.appLayer.disconnectClient(
                    204, 'CLIENT_DISCONNECTION')
                break
            logging.info('client address %s sent %i bytes' %
                         (_clientAddress, _dataReceived.__len__()))
            # TODO set timeout for server requests
            if not any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress):
                if not AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                    authentication_result = self.appLayer.authenticate(
                        _dataReceived)
                    if any(x[1] for x in AUTHORIZED_CLIENTS if x[1] == self.appLayer.c_id):
                        _response = self.appLayer.disconnectClient(
                            400, 'AUTHENTICATION_FAILED')
                        self.request.send(_response)
                        break
                    if not authentication_result[0]:
                        _response = self.appLayer.disconnectClient(
                            400, 'AUTHENTICATION_FAILED')
                        self.request.send(_response)
                        break
                    self.request.send(authentication_result[1])
                    t0 = time.time()
                elif (time.time() - t0) < 5.01:
                    authorization_result = self.appLayer.authorize(
                        _dataReceived)
                    if not authorization_result[0]:
                        _response = self.appLayer.disconnectClient(
                            401, 'AUTHORIZATION_FAILED')
                        self.request.send(_response)
                        break
                    self.request.send(authorization_result[1])
                else:
                    _response = self.appLayer.disconnectClient(
                        408, 'AUTHORIZATION_TIMEOUT')
                    self.request.send(_response)
                    break
            else:
                _request = messageFormation.extractReqData(_dataReceived)
                if _request.__len__() == 0:
                    _response = self.appLayer.disconnectClient(
                        406, 'UNDIFIEND_REQUEST')
                    self.request.send(_response)
                    break
                _response = messageFormation.makeResponse('CORRECT', 200)
                self.request.send(_response)
