import tcpServer

SOCKET_PORT = 8001

if __name__ == "__main__":
    myServer = tcpServer.SocketServer(SOCKET_PORT)
    myServer.Server.serve_forever()
