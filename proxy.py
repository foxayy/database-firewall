#!/usr/bin/python
# -*- coding: UTF-8 -*-
from socket import *
import os
from sklearn.externals import joblib
import learn
import signal
import config
import httpserver
import threading

def MySQLGetUsernameDB(data):
    if len(data)<33:
        return
    pos = 32

    nullByteIndex = IndexByte(data[pos:])
    username = data[pos:nullByteIndex + pos]
    pos += nullByteIndex + 22
    nullByteIndex = IndexByte(data[pos:])

    #Check if DB name is selected
    dbSelectedCheck = len(data) > nullByteIndex+pos+1

    if nullByteIndex != 0 and dbSelectedCheck:
	db = data[pos:nullByteIndex + pos]
	return username,db
    return

def IndexByte(data):
    for index,value in enumerate(data):
        if ord(value) == 0:
            return index
    return -1

def signal_handler(signum, frame):
    print('Shutting down...')
    tcpSerSock.close()
    exit(0)

def log(query,result,action) :
    try :
        f = open(logPath,'a')
        line = query + ',' + result + ',' +action + '\n'
        f.writelines(line)
    finally :
        if f :
            f.close()

def readlog(logPath):
    t = 0
    a = 0
    with open(logPath, 'r') as f:
        for line in f.readlines():
            index = len(line)-6
            if line[index-1] == 's':
                t += 1
                a += 1
            else:
                t += 1
    return t,a

conf = config.config()
if conf == None :
    exit(1)

signal.signal(signal.SIGINT, signal_handler)

dataframe, df_stats = learn.load_dataframe_dfstats()
#判断模型是否存在
isexists = os.path.exists("./model/train_model.m")
if not isexists :
    learn.transform_fit_save(dataframe, df_stats)
print 'Model loaded'
clf = joblib.load("./model/train_model.m")

# 服务器创建socket，绑定到端口，开始监听
tcpSerPort = conf['listenport']
tcpSerIp = conf['listenip']
databasePort = conf['targetport']
databaseIp = conf['targetip']
httpSSL = conf['httpSSL']
httpIP = conf['httpIP']
httpPort = conf['httpPort']
httpPassword = conf['httpPassword']
logPath = conf['logPath']

httpserver.total,httpserver.abnormal = readlog(logPath)

t =threading.Thread(target=httpserver.server,args=(httpIP,httpPort,httpPassword,))
t.setDaemon(True)#设置线程为后台线程
t.start()

tcpSerSock = socket(AF_INET, SOCK_STREAM)

# Prepare a server socket
tcpSerSock.bind((tcpSerIp, tcpSerPort))

while True :
    tcpSerSock.listen(1)
    # 开始从客户端接收请求
    print 'Ready to serve...'
    CliSock, addr = tcpSerSock.accept()
    print 'Received a connection from: ', addr
    # 客户端创建socket，绑定到端口，开始监听
    tcpCliSock = socket(AF_INET, SOCK_STREAM)
    tcpCliSock.connect((databaseIp,databasePort))
    welcome = tcpCliSock.recv(1024)
    print 'Database welcome'
    CliSock.send(welcome)
    message = CliSock.recv(1024)
    data = message[4:]
    # 从请求中解析出用户名和数据库类型
    username,dbname = MySQLGetUsernameDB(data)
    print 'Username:',username
    print 'dbname:',dbname
    # check if ssl is required
    ssl = (ord(data[1]) & 0x08) == 0x08
    # Send Login Request
    tcpCliSock.send(message)
    if ssl:
        print "ssl server is open"
        # 待补充，mysql.go的handlelogin（）
        # ....
        #####
    print 'SSL bit:',ssl
    if len(dbname) != 0 : # db Selected
	# Receive OK
	sta = tcpCliSock.recv(1024)
    else :
        # Receive Auth Switch Request
	req = tcpCliSock.recv(1024)
        # Receive Auth Switch Response
        res = tcpCliSock.recv(1024)
        # Receive Response Status
        sta = tcpCliSock.recv(1024)
     
    #Send Response Status
    CliSock.send(sta)
    if ord(sta[5]) != 0x15 :
	success = 1
    else :
        success = 0
    if not success :
	print "Login failed"
        break
    while 1 :
	buf = CliSock.recv(1024)
	if len(buf) < 5 :
	    break
	data = buf[4:]
	if ord(data[0]) == 0x01 : #Quit
            break
	elif ord(data[0]) == 0x02: #UseDB
            currentDB = data[1:]
	    print("Using database: %v", currentDB)
	elif ord(data[0]) == 0x03: #Query
	    query = data[1:]

        result = learn.load_predict(query, df_stats, clf)

        #result是legit则发送给服务器，否则终端连接
	if result == "legit" :
            httpserver.total += 1
            log(query,'legit','pass')
            tcpCliSock.send(buf)
            #Recive response
	    response = tcpCliSock.recv(1024)
            CliSock.send(response)
        else :
            httpserver.total += 1
            httpserver.abnormal += 1
            print 'malicious query'
            log(query,'malicious','drop')
            break
    # Close the client and the server sockets
    CliSock.close()
    tcpCliSock.close()
    # Fill in start.
