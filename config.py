# !/usr/bin/env python
# -*- coding:utf-8 -*-  

import ConfigParser
import os

def config():

    cf = ConfigParser.ConfigParser()
    isexists = os.path.exists("./config.ini")
    if isexists :
        cf.read("./config.ini")
    else :
        print 'config not found'
        return

    mode = cf.get("Generel", "mode")
    dbms = cf.get("Generel", "dbms")
    listenip = cf.get("Generel", "listenip")
    listenport = cf.get("Generel", "listenport")
    listenport = int(listenport)
    targetip = cf.get("Generel", "targetip")
    targetport = cf.get("Generel", "targetport")
    targetport = int(targetport)

    logPath = cf.get("Logging", "logPath")

    httpSSL = cf.get("HttpService", "httpSSL")
    httpIP = cf.get("HttpService", "httpIP")
    httpPort = cf.get("HttpService", "httpPort")
    httpPort = int(httpPort)
    httpPassword = cf.get("HttpService", "httpPassword")

    conf = {'mode': mode, 'dbms': dbms, 'listenip': listenip, 'listenport': listenport, 'targetip': targetip, 'targetport': targetport, 'logPath': logPath, 'httpSSL': httpSSL, 'httpIP': httpIP, 'httpPort': httpPort, 'httpPassword': httpPassword}
    return conf
