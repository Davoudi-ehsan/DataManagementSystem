import tcpServer

if __name__ == "__main__":
    myServer = tcpServer.SocketServer(8001)
    myServer.Server.serve_forever()
