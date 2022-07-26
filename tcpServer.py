import logging
import socketserver
import appLayer
import time


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
                self.appLayer.disconnectClient()
                logging.warn('client address %s disconnected' % _clientAddress)
                break
            logging.info('client address %s sent %i bytes' %
                         (_clientAddress, _dataReceived.__len__()))
            if not self.appLayer.AUTHORIZED_CLIENTS.__contains__(_clientAddress):
                if not self.appLayer.AUTHENTICATED_CLIENTS.__contains__(_clientAddress):
                    authentication_result = self.appLayer.authenticate(
                        _dataReceived)
                    self.request.send(authentication_result[1])
                    if not authentication_result[0]:
                        logging.warn(
                            'client address %s disconnected duo to AUTHENTICATION_FAILED' % _clientAddress)
                        break
                    logging.info('client address %s authenticated' %
                                 _clientAddress)
                    t0 = time.time()
                elif (time.time() - t0) < 5.01:
                    authorization_result = self.appLayer.authorize(
                        _dataReceived)
                    self.request.send(authorization_result[1])
                    if not authorization_result[0]:
                        self.appLayer.disconnectClient()
                        logging.warn(
                            'client address %s disconnected duo to AUTHORIZATION_FAILED' % _clientAddress)
                        break
                    logging.info('client address %s authorized' %
                                 _clientAddress)
                else:
                    _response = self.appLayer.makeResponse('ERROR', 408)
                    self.request.send(_response)
                    self.appLayer.disconnectClient()
                    logging.warn(
                        'client address %s disconnected duo to AUTHORIZATION_TIMEOUT' % _clientAddress)
                    break
            else:
                _request = self.appLayer.extractReqData(_dataReceived)
                if _request.__len__() == 0:
                    _response = self.appLayer.makeResponse('ERROR', 406)
                    self.request.send(_response)
                    self.appLayer.disconnectClient()
                    logging.warn(
                        'client address %s disconnected duo to UNDIFIEND_REQUEST' % _clientAddress)
                    break
                _response = self.appLayer.makeResponse('CORRECT', 200)
                self.request.send(_response)
