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
import socket
import atexit
#import syslog
from yaml import load
import sqlite3 
from pathlib import Path
import argparse
parser = argparse.ArgumentParser()
import signal

parser.add_argument("-d","--debug", help="Запуск в режиме отладки", default=False,
                    action="store_true")
parser.add_argument("-f","--foreground", help="Консольный режим. Вывод статистики во время работы.", default=False,
                    action="store_true")

args = parser.parse_args()

ON_POSIX = 'posix' in sys.builtin_module_names

# грузим конфиг
with open('config.yml', 'r') as f:
    cfg = load(f)

dbtype = cfg['dbtype']

def finish(signalNumber, frame):
    """: очистка iptables при выходе"""
    #p.kill() # supported from python 2.6
    delrules()
    print('iptables cleaned up')
    atexit.unregister(finish2)
    exit(0)

def finish2():
    """: очистка iptables при выходе"""
    #p.kill() # supported from python 2.6
    delrules()
    print('iptables cleaned up 2')

def prnmsg(level,data):
    """: печать сообщения с тагом 
    @param level    текст тега
    @param data     сам текст
    """
    data = "[{}]: {}           ".format(level,data)
    print(data)

def logErr(data):
    """: печать ошибки
    @param data текст ошибки
    """
    prnmsg("ERROR",data)

def logCrit(data):
    """: печать критической ошибки
    @param data текст ошибки
    """
    prnmsg("CRITICAL",data)

def logInfo(data):
    """: печать информационного сообщения
    @param data текст ошибки
    """
    prnmsg("NOTICE",data)

def logDbg(data):
    """: печать отладочного сообщения
    @param data текст ошибки
    """
    if args.debug:
        prnmsg("DEBUG",data)

def nowsec():
    """: текущее время в секундах
    @return время в секундах
    """
    return round(time.time())

def delrules():
    """: Удаление правил iptables созданных при запуске."""

    logInfo("Очистка правил iptables")
    try:
        out = subprocess.check_output("iptables -D INPUT -p tcp -j s2blog", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить правило журналирования")

    try:
        out = subprocess.check_output("iptables -D INPUT -j s2bdrop", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить правило перехвата")

    try:
        out = subprocess.check_output("iptables -F s2bdrop", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить правила из s2bdrop")

    try:
        out = subprocess.check_output("iptables -X s2bdrop", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить цепочку s2bdrop")

    try:
        out = subprocess.check_output("iptables -F s2blog", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить правила из цепочки s2blog")

    try:
        out = subprocess.check_output("iptables -X s2blog", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить цепочку s2blog")

    try:
        out = subprocess.check_output("iptables -F s2bdroplog", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить правила из цепочки s2bdroplog")

    try:
        out = subprocess.check_output("iptables -X s2bdroplog", shell=True)
    except subprocess.CalledProcessError as out:
        logErr("Не удалось удалить цепочку s2bdroplog")

# инициализируем iptables
def initrules():
    """: Добавление правил в iptables."""
    logInfo("Подготовка iptables")
    ## цепочка для блокировок
    try:
        out = subprocess.check_output("iptables" + " -N" + " s2bdrop", shell=True)
    except subprocess.CalledProcessError as out:
        print("error code", out.returncode, out.output)
        logErr("Цепочка 's2bdrop' не должна существовать до запуска")
        exit(2)

    ## цепочка журналирования блокировок
    try:
        out = subprocess.check_output("iptables" + " -N" + " s2bdroplog", shell=True)
    except subprocess.CalledProcessError as out:
        print("error code", out.returncode, out.output)
        logErr("Цепочка 's2bdrop' не должна существовать до запуска")
        exit(2)

    ## цепочка журналирования 
    try:
        out = subprocess.check_output("iptables" + " -N" + " s2blog", shell=True)
        for i in cfg['ignored_nets']:
            logInfo("Добавляем игнорируемую сеть: %s" % i)
            out = subprocess.check_output("iptables -A s2blog -s %s -j RETURN" % i, shell=True)

        if cfg['fwlogmode'] == 'log':
            out = subprocess.check_output("iptables -A s2blog -j LOG --log-prefix '[S2BLOG]: ' --log-level 7", shell=True)
        elif cfg['fwlogmode'] =='nflog':
            out = subprocess.check_output("iptables -A s2blog -j NFLOG --nflog-prefix '[S2BLOG]: '", shell=True)
        else:
            logCrit("Неизвестный тип iptables log: %s" % cfg['fwlogmode'])
            exit(2)

    except subprocess.CalledProcessError as out:
        print("error code", out.returncode, out.output)
        logErr("Цепочка 's2bdrop' не должна существовать до запуска")
        exit(2)

    ## правило журналирования в конец цепочки s2bdroplog
    try:
        if cfg['fwlogmode'] == 'log':
            out = subprocess.check_output("iptables -A s2bdroplog -j LOG --log-prefix '[DROP][S2BLOG]: ' --log-level 7", shell=True)
        elif cfg['fwlogmode'] =='nflog':
            out = subprocess.check_output("iptables -A s2bdroplog -j NFLOG --nflog-prefix '[DROP][S2BLOG]: '", shell=True)
        else:
            logCrit("Неизвестный тип iptables log: %s" % config['fwlogmode'])
            exit(2)
    except subprocess.CalledProcessError as out:
        print("error code", out.returncode, out.output)
        logErr("Не удалось добавить правило журналирования")
        exit(2)

    ## правило блокировки в конец цепочки s2bdroplog
    try:
        out = subprocess.check_output("iptables -A s2bdroplog -j DROP", shell=True)
    except subprocess.CalledProcessError as out:
        print("error code", out.returncode, out.output)
        logErr("Не удалось добавить правило журналирования")
        exit(2)

    ## правило журналирования в конец цепочки INPUT
    try:
        out = subprocess.check_output("iptables -A INPUT -p tcp -j s2blog", shell=True)
    except subprocess.CalledProcessError as out:
        print("error code", out.returncode, out.output)
        logErr("Не удалось добавить правило журналирования")
        exit(2)
    
    ## прыжок на цепочку блокировки в начало INPUT
    try:
        out = subprocess.check_output("iptables -I INPUT -j s2bdrop", shell=True)
    except subprocess.CalledProcessError as out:
        print("error code", out.returncode, out.output)
        logErr("Не удалось добавить правило перехвата")
        exit(2)

def enqueue_output(out, queue):
    """: Сохранение считанного сообщения в очередь
    @param out  обрабатываемый список строк
    @param queue    очередь куда все закидываем
    """
    for line in iter(out.readline, b''):
        ## b'' из out без конвертации на извлечении из очерели теряет кодировку
        queue.put(str(line,'utf-8'))
    out.close()

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

    try: 
        if cfg['dbtype'] == 'sqlite3':
            cur.execute("""CREATE TABLE IF NOT EXISTS ips(ip INTEGER NOT NULL PRIMARY KEY,count INTEGER,block INTEGER,last INT); """)
            cur.execute("""CREATE TABLE IF NOT EXISTS details(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,src INTEGER NOT NULL,dst INTEGER NOT NULL,port INTEGER NOT NULL,time INT); """)
        elif cfg['dbtype'] == 'pg':
            cur.execute("""CREATE TABLE IF NOT EXISTS ips(ip BIGINT NOT NULL PRIMARY KEY,count INTEGER,block SMALLINT,last INT); """)
            cur.execute("""CREATE TABLE IF NOT EXISTS details(id serial PRIMARY KEY,src BIGINT NOT NULL,dst BIGINT NOT NULL,port INTEGER NOT NULL,time INT); """)
        else:
            logCrit("Ошибка создания таблиц")
            sys.exit(2)

        sql.commit()
        logInfo("База данных '%s:%s' подключена" % (dbtype,cfg['db']))
        return sql,cur
    except  Exception as err:
        logCrit("Ошибка при подключении бд: %s" % (str(err)))
        sys.exit(2)

def adaptSQL(s):
    """: конвертация запроса в формат pg"""
    if dbtype == 'pg':
        return s.replace('?','%s')
    return(s)

def parse(line):
    """: разбор строки
    @param  line    строка для анализа
    """

    global linec,linecipt ## глобальные счетчики
    linec += 1

    ## пропускаем все что не от нашего правила
    m = re.search("S2BLOG.*SRC=([\S]*).*DST=([\S]*).*DPT=([\d]*)",line)
    if m:
        linecipt += 1
        logDbg(line)

        ## переназначаем переменные в человеческий вид
        src = m[1] 
        srcl = ip2long(src) ## окончание 'l' == long
        dst = m[2] 
        dstl = ip2long(dst)
        port = m[3]
        logDbg("IP: %s( %d) -> %s(%d):%s" % (src,srcl,dst,dstl,port))

        n = re.search("DROP..IPT",line)
        ## если правило из цепочки дропов, взводим переменную drop
        if n:
            drop = 1
        else:
            drop = 0
        logDbg("Пакет в цепочке s2bdroplog: %s" % drop)
        
        q = "SELECT count from ips WHERE ip = %d" % srcl
        cur.execute(q)
        record = cur.fetchone()

        ## src отсутствует в ips, добавляем в бд
        if record == None:
            logInfo("Новый адрес: %s              " % src)
            try:
                cmd = "INSERT INTO ips (ip,count,block,last) VALUES (?,?,0,?);"
                cmd = adaptSQL(cmd)
                ## время жизни для адреса текущее + blocktime
                tuple = (srcl,0,nowsec() + cfg['blocktime'])
                cur.execute(cmd,tuple)
                sql.commit()
            except sqlite3.Error as err:
                logErr("Failed to add ips: %s" % err)

        else:
            logDbg("Счетчик для адреса: %s" % record[0])

        ## вносим запись о событии в details
        try:
            cmd = """INSERT INTO details (src,dst,port,time) VALUES (?,?,?,?);"""
            cmd = adaptSQL(cmd)
            tuple = (srcl,dstl,port,nowsec())
            cur.execute(cmd,tuple)
            sql.commit()
        except sqlite3.Error as err:
            logErr("Failed to add details: %s" % err)

        ## если порт не в списке игнорируемых, увеличиваем счетчик и обновляем запись в бд
        if port not in cfg['ignored_ports']:
            logDbg("Увеличиваем счетчик")
            try:
                cmd = """UPDATE ips SET count = count + 1, last = ? WHERE ip = ?;"""
                cmd = adaptSQL(cmd)
                logDbg("now: %s, last: %s" % (nowsec(),nowsec() + cfg['blocktime']))
                ## время жизни текущее + blocktime
                tuple = (nowsec() + cfg['blocktime'],srcl)
                cur.execute(cmd,tuple)
                sql.commit()
            except sqlite3.Error as err:
                logErr("Failed to inc counter %s" % err)
        else:
            logDbg("Порт в игнорируемом списке")

        ## если счетчик больше порога и drop != 1, добавляем адрес в цепочку блокировок и обновляем таблицу в бд
        cmd = """SELECT count,block from ips WHERE ip = ?;""" 
        cmd = adaptSQL(cmd)
        tuple = (srcl,)
        try:
            cur.execute(cmd,tuple)
            record = cur.fetchone()
        except sqlite3.Error as err:
            logErr("Failed to select counter")

        ## учитывается в т.ч. локальный словарь блокировок, т.к. если пакеты пришли серией, то все они попали в очередь сообщение без тега DROP
        if drop != 1 and src not in nowblocked:
            logDbg("Адрес не заблокирован")

            ## блокируем если превышен порог или порт в списке instant_ports
            if record[0] > cfg['blockcnt']:
                logInfo("Блокируем по blockcnt: %s" % src)
                addIPTRule(src,"count") # добавляем правило в iptables
                updateDBIPState(src) # ставим флаг блокировки в записи бд
            elif int(port) in cfg['instant_ports']:
                logInfo("Блокируем по instant_port: %s:%s" % (src,port))
                addIPTRule(src,"instant")
                updateDBIPState(src)
        else:
            logDbg("Адрес  заблокирован")

def loadBlocked():
    """: заполняем цепочку блокировок данными из бд"""
    q = """SELECT ip,block FROM ips;"""
    cur.execute(q)
    records = cur.fetchall()
    blocked = 0 ## счетчик заблокированных адресов
    ignored = 0 ## счетчик игнорируемых адресов
    for row in records:
        ip=long2ip(row[0])
        block=row[1]
        if block == 1:
            logDbg("Блокируется: %s" % (ip))
            addIPTRule(ip,"startup")
            blocked += 1
        else:
            logDbg("Пропускается адрес: %s" % (ip))
            ignored += 1
    logInfo("Добавлено правил блокировки: %s, пропущено адресов: %s" % (blocked,ignored))

def addIPTRule(src,msg):
    """: добавление правила переправление в цепочку блокировки.
    @param src  адрес
    @param msg  комментарий
    """
    global nowblocked,nowblockedcomm
    run(["iptables", "-I","s2bdrop","-s",src,"-j","s2bdroplog","-m","comment","--comment",msg])
    nowblocked[src] = 1
    nowblockedcomm[src] = msg

def delIPTRule(src):
    """: удаление правила пенеправление в цепочку блокировки."""
    global nowblocked,nowblockedcomm
    run(["iptables", "-D","s2bdrop","-s",src,"-j","s2bdroplog","-m","comment","--comment",nowblockedcomm[src]])
    del nowblocked[src],nowblockedcomm[src]

def updateDBIPState(src):
    """: указываем в таблице ips что адрес заблокирован """
    srcl=ip2long(src)
    try:
        cmd = """UPDATE ips SET block = 1 WHERE ip = ?;"""
        cmd = adaptSQL(cmd)
        #  если без запятой, буде ValueError: https://qna.habr.com/q/968641
        tuple = (srcl,)
        cur.execute(cmd,tuple)
        sql.commit()
    except sqlite3.Error as err:
        logErr("Failed to inc counter %s" % err)

def syncBlocks():
    """: синхронизация в два прохода. В начале выявляем правила добавленые в таблицу другими участниками и добавляем их в цепочку. Затем проходим локальные блокировки и если их нет в базе - удаляем. Таким образом если блокировки были добавлены другими участниками, они попадут к нам, а если они были удалены другими участниками - у себя мы их тоже удалим.
    """
    logDbg("Выполняется синхронизация блокировок")
    ## выгружаем блокировки из базы и добавляем в локальные правила те, которых нет
    dbblocks = {} ## словарь заблокированных адресов
    q = "SELECT ip from ips WHERE block = 1;"""
    cur.execute(q)
    records = cur.fetchall()
    for row in records:
        ip = long2ip(row[0])
        dbblocks[ip] = 1 ## заполняем словарь для использования в следующем блоке
        if ip not in nowblocked:
            logInfo("Блокируем по бд: %s" % ip)
            addIPTRule(ip,"db")

    ## прогоняем все локальные блокировки. Если блокировки нет в базе - удаляем из правил.
    for ip in list(nowblocked):
        if ip not in dbblocks:
            logInfo("Удаляем блокировку по бд: %s" % ip)
            delIPTRule(ip)

def cleanBlocks():
    logDbg("Выполняется цикл проверки времени жизни блокировок")

    ## выбираем адреса для которых счетчик выше порога, а last меньше чем текущее время
    cmd = """SELECT ip,count,last from ips WHERE last < ?;""" 
    cmd = adaptSQL(cmd)
    tuple = (nowsec(),)
    try:
        cur.execute(cmd,tuple)
        records = cur.fetchall()
    except sqlite3.Error as err:
        logErr("Failed to select counter")
    ## удаляем соответствующие строки из iptables
    for row in records:
        srcl = row[0]
        src = long2ip(srcl)
        count = row[1]
        logInfo("Истечение времени неактивности для адреса: %s, пакетов: %d" % (src,count))
        ## из iptables удалется только если счетчик выше порога, т.к. иначе правила там нет
        # FIXME ne vipolnyaetsa dlia instant_ports
        if count > cfg['blockcnt']:
            logDbg("Удаление правила iptables")
            delIPTRule(src)
    ## удаляем соответствующие строки из бд
        logDbg("Удаление записи из бд")
        try:
            cmd = """DELETE from ips  WHERE ip = ?;"""
            cmd = adaptSQL(cmd)
            #  если без запятой, буде ValueError: https://qna.habr.com/q/968641
            tuple = (srcl,)
            cur.execute(cmd,tuple)
            sql.commit()
        except sqlite3.Error as err:
            logErr("Failed to inc counter %s" % err)

## основная секция

#ips={}
#ipsc={}
nowblocked={} ## словарь локальных блокировок
nowblockedcomm={} ## комментарии к правилам. нужны при удалении.

## цепляемся к базе
(sql,cur) = initDb()

##  регистрируем функцию выхода
# https://stackabuse.com/handling-unix-signals-in-python/
# FIXME: при ctrl-c валится со стектрейсом
signal.signal(signal.SIGTERM, finish) ## systemd kill
#signal.signal(signal.SIGINT, finish) ## ctrl-c
atexit.register(finish2)

# готовим iptables
initrules() ## создаем цепочки и минимальные правила

loadBlocked() ## заполняем блокировками из бд

logDbg("Контрольная команда: " + cfg['moncmd']) 

# запускаем процесс наблюдения, вывод складываем в очередь
p = Popen(cfg['moncmd'], shell=True, stdout = PIPE, bufsize=1,  close_fds=ON_POSIX)
q = Queue()
t = Thread(target=enqueue_output, args=(p.stdout, q))
t.daemon = True # thread dies with the program
t.start()

linec = 0 # число обработанных строк
linecipt = 0 # число обработанных строк

lastclean=nowsec() # время последней очистки
lastsync=nowsec() # время последней синхронизации

while True:
    try:
        line = q.get_nowait() # or q.get(timeout=.1)
    except Empty:
        ecode=p.poll()
        if(ecode != None):
            #  subprocess exited
            msgerr("Subprocess exited wihth code: {}".format(ecode))
            exit(2)
        sleep(1)
    else: # got line
        parse(line)
        if args.foreground:
            print("[%d] Обработано строк: %s, из них s2blog: %s" % (nowsec(),linec,linecipt),end='\r')

    if nowsec() > lastclean + cfg['cleanperiod']:
        cleanBlocks() ## проверяем таймеры на адреса
        lastclean = nowsec()
    if nowsec() > lastsync + cfg['syncperiod']:
        syncBlocks() ## синхронизируем состояние базы и локальной таблицы
        lastsync = nowsec()
