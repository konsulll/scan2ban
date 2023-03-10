#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

import time
from subprocess import run,PIPE, Popen, STDOUT
import subprocess
import select
import sys
import fcntl
from queue import Queue, Empty
from threading  import Thread
from time import sleep
import re
import datetime
from datetime import datetime
import socket
import atexit
import syslog
from yaml import load
import sqlite3 
from pathlib import Path
import argparse
parser = argparse.ArgumentParser()
import signal

parser.add_argument("-a","--all", help="Полная выгрузка", default=False,
                    action="store_true")
parser.add_argument("--pretty", help="С отступами", default=False,
                    action="store_true")
parser.add_argument("--human", help="Читаемый вывод", default=False,
                    action="store_true")

args = parser.parse_args()

ON_POSIX = 'posix' in sys.builtin_module_names

# грузим конфиг
with open('config.yml', 'r') as f:
    cfg = load(f)

import socket, struct
def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def long2ip(num):
    """
    Convert an long to IP
    """
    return socket.inet_ntoa(struct.pack('!L', num))


def initDb():
    """: инициализация или подключение бд.
    @return указатель на соединие с бд и курсор
    """
    try:
        if cfg['dbtype'] == 'sqlite3':
            sql = sqlite3.connect(cfg['db'])
        elif cfg['dbtype'] == 'pg':
            import psycopg2
            sql = psycopg2.connect(dbname=cfg['db'], user=cfg['dbuser'], password=cfg['dbpass'], host=cfg['dbhost'],port=cfg['dbport'])
        else:
            logCrit("Неизвестный тип бд: %s" % cfg['dbtype'])
            sys.exit(2)
            
        cur = sql.cursor()
    except Exception as err:
        logCrit("Ошибка при подключении бд: %s" % (str(err)))
        sys.exit(2)
    return(sql,cur)

## цепляемся к базе
(sql,cur) = initDb()

if args.all == True:
    q = """SELECT ip,count,block,last FROM ips;"""
else:
    q = """SELECT ip,count,block,last FROM ips where block=1;"""
cur.execute(q)
records = cur.fetchall()
for row in records:
    ipl=row[0]
    count=row[1]
    block=row[2]
    last=row[3]

    if args.human == True:
        print("%s,%s,%s,%s" % (long2ip(ipl),count,block,datetime.fromtimestamp(last)))
    else:
        print("%s,%s,%s,%s" % (ipl,count,block,last))
