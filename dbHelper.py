import mysql.connector
import json
import logging


class dbhelper:
    def __init__(self):
        try:
            f = open('.env/db_info.json')
            db_login = json.load(f)['login']
            self.cnx = mysql.connector.connect(user=db_login['user'], password=db_login['password'],
                                               host=db_login['host'], port=db_login['port'],
                                               database=db_login['database'])
        except:
            self.cnx = None
            logging.error("database connection failed")

    def selectData(self, query):
        if self.cnx is None:
            return None
        if not self.cnx.is_connected():
            self.__init__()
        cursor = self.cnx.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        if result.__len__() == 0:
            return None
        self.cnx.close()
        return result

    def executeQuery(self, query):
        if self.cnx is None:
            return None
        if not self.cnx.is_connected():
            self.__init__()
        cursor = self.cnx.cursor()
        cursor.execute(query)
        self.cnx.commit()
        return 1
