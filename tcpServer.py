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
        t0 = time.time()
        while 1:
            # check if there is any request for client
            if self.serverRequest.__len__() > 0:
                self.request.send(self.serverRequest)
                logging.info(
                    "server's request sent to client address %s" % _clientAddress)
                self.serverRequest = bytearray()
            # wait for receive packet from client
            _dataReceived = self.request.recv(1024)
            if not _dataReceived:
                _response = self.appLayer.disconnectClient(
                    204, 'CLIENT_DISCONNECTION')
                break
            logging.info('client address %s sent %i bytes' %
                         (_clientAddress, _dataReceived.__len__()))
            # TODO set timeout for server requests
            # analyze received packet
            _request = messageFormation.extractReqData(_dataReceived)
            _requestType = [
                value[1] for value in _request if value[0] == 'req_type']
            if _requestType.__len__() == 0:
                _response = self.appLayer.disconnectClient(
                    406, 'WRONG_REQUEST')
                self.request.send(_response)
                break
            # determine content of recieved packet
            match _requestType[0]:
                case 'AUTHENTICATION':
                    # check client for already AUTHORIZATION or AUTHENTICATION
                    if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                            AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                        _response = self.appLayer.disconnectClient(
                            406, 'WRONG_REQUEST')
                        self.request.send(_response)
                        break
                    authentication_result = self.appLayer.authenticate(
                        _request)
                    # check client for c_id duplication and wrong AUTHENTICATION response
                    if any(x[1] for x in AUTHORIZED_CLIENTS if x[1] == self.appLayer.c_id) or \
                            not authentication_result[0]:
                        _response = self.appLayer.disconnectClient(
                            400, 'AUTHENTICATION_FAILED')
                        self.request.send(_response)
                        break
                    _response = authentication_result[1]
                    self.request.send(_response)
                    t0 = time.time()
                case 'AUTHORIZATION':
                    # check client for already AUTHORIZATION or AUTHENTICATION
                    if any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress) or \
                            not AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                        _response = self.appLayer.disconnectClient(
                            406, 'WRONG_REQUEST')
                        self.request.send(_response)
                        break
                    # check for timeout
                    if (time.time() - t0) < 5.01:
                        authorization_result = self.appLayer.authorize(
                            _request)
                        # check client for wrong AUTHORIZATION response
                        if not authorization_result[0]:
                            _response = self.appLayer.disconnectClient(
                                401, 'AUTHORIZATION_FAILED')
                            self.request.send(_response)
                            break
                        _response = authorization_result[1]
                        self.request.send(_response)
                    else:
                        _response = self.appLayer.disconnectClient(
                            408, 'AUTHORIZATION_TIMEOUT')
                        self.request.send(_response)
                        break
                case 'READING':
                    if not any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress):
                        _response = self.appLayer.disconnectClient(
                            406, 'WRONG_REQUEST')
                        self.request.send(_response)
                        break
                    pass
                case 'WRITING':
                    if not any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress):
                        _response = self.appLayer.disconnectClient(
                            406, 'WRONG_REQUEST')
                        self.request.send(_response)
                        break
                    pass
                case 'EXECUTION':
                    if not any(x[0] for x in AUTHORIZED_CLIENTS if x[0] == _clientAddress):
                        _response = self.appLayer.disconnectClient(
                            406, 'WRONG_REQUEST')
                        self.request.send(_response)
                        break
                    pass
