CREATE TABLE IF NOT EXISTS ips(ip INTEGER NOT NULL PRIMARY KEY,count INTEGER,block INTEGER,last INT); 
CREATE TABLE IF NOT EXISTS details(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,src INTEGER,dst INTEGER,port INTEGER,note TEXT,time INT);