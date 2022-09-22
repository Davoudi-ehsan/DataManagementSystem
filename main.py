import tcpServer
import dbHelper

SOCKET_PORT = 8001

if __name__ == "__main__":
    _database = dbHelper.dbhelper()
    if _database:
        if _database.check_database_tables():
            myServer = tcpServer.SocketServer(SOCKET_PORT)
            if myServer.Server:
                myServer.Server.serve_forever()
