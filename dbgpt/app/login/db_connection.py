import pymysql

from dbgpt._private.config import Config

CFG = Config()


# 连接到MySQL数据库
def connect_to_database():
    connection = pymysql.connect(
        host=CFG.LOCAL_DB_HOST,
        user=CFG.LOCAL_DB_USER,
        password=CFG.LOCAL_DB_PASSWORD,
        database=CFG.LOCAL_DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
    )
    return connection
