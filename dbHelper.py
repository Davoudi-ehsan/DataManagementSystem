import mysql.connector
import json
import logging
import queries
from pathlib import Path

# config logging function
BASE_DIR = Path(__file__).resolve().parent
FORMAT = '''{ "time": "%(asctime)s", "level": "%(levelname)s", "module": "%(modulename)s", "message": "%(message)s" }'''
logging.basicConfig(
    filename=BASE_DIR / 'application_logs.json',
    format=FORMAT,
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')
EXTRA = {'modulename': __name__}


class dbhelper:
    def __init__(self):
        try:
            self.read_dbInfo()
            self.cnx = mysql.connector.connect(user=self.db_login['user'], password=self.db_login['password'],
                                               host=self.db_login['host'], port=self.db_login['port'],
                                               database=self.db_login['database'])
        except Exception as e:
            self.cnx = None
            logging.error('database connection failed',
                          extra=EXTRA, exc_info=e)

    def check_database_tables(self):
        if not self.cnx:
            return None
        if not self.cnx.is_connected():
            self.__init__()
        cursor = self.cnx.cursor()
        try:
            cursor.execute('SHOW TABLES')
            result = cursor.fetchall()
            for table in self.db_mainTables.keys():
                existed_table = [x[0] for x in result if x[0] == table]
                if existed_table.__len__() == 0:
                    _query = queries.MAIN_TABLES[table].replace('\n', '')
                    cursor.execute(_query)
                    self.cnx.commit()
                    logging.info('database.%s created' % table, extra=EXTRA)
            cursor.close()
            logging.info(
                'checking existance of main tables finished', extra=EXTRA)
            return True
        except Exception as e:
            logging.error(
                'checking existance of main tables did not finish', extra=EXTRA, exc_info=e)
            return None

    def selectData(self, query):
        if not self.cnx:
            return None
        if not self.cnx.is_connected():
            self.__init__()
        cursor = self.cnx.cursor()
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            if result.__len__() == 0:
                return None
            cursor.close()
            return result
        except Exception as e:
            logging.error('database selection failed', extra=EXTRA, exc_info=e)
            return None

    def executeQuery(self, query):
        if not self.cnx:
            return None
        if not self.cnx.is_connected():
            self.__init__()
        cursor = self.cnx.cursor()
        try:
            cursor.execute(query)
            self.cnx.commit()
            cursor.close()
            return True
        except Exception as e:
            logging.error('database execution failed', extra=EXTRA, exc_info=e)
            return False

    def read_dbInfo(self):
        try:
            f = open('.env/db_info.json', 'r')
            _json_file = json.load(f)
            f.close()
            self.db_mainTables = _json_file['main-tables']
            self.db_login = _json_file['login']
        except Exception:
            logging.error('reading json file failed', extra=EXTRA)
