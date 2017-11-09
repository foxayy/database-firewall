#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import json

assets = "assets"
global total
global abnormal

def HttpResponse(header,whtml):
    f = file(whtml)
    contxtlist = f.readlines()
    context = ''.join(contxtlist)
    response = "%s %d\n\n%s\n\n" % (header,len(context),context)
    return response

def requestparse(data):
    reqindex = data.find('\n')
    data = data[:reqindex-1]
    request = []
    reqindex = data.find(' ')
    request.append(data[:reqindex]) #acquire the request method
    data = data[reqindex+1:]
    reqindex = data.find(' ')
    request.append(data[:reqindex]) #acquire request url
    data = data[reqindex+1:]
    request.append(data)  # acquire request protocol
    return request

def mainlistener(httpheader,conn):
    servefile(httpheader,conn,"assets/index.htm")

def servefile(httpheader,conn,root):
    conn.send(HttpResponse(httpheader,root))

def apihandler(conn):
    #print "total:%d, abnormal:%d"%(total,abnormal)
    data = json.dumps({'Total': total,'Abnormal':abnormal})
    conn.send(data)

def loginhandler(httpheader,conn,data,passwd):
    #extract password
    startindex = data.find("password")
    password = str(data[startindex+9:]) #这项没有回车符

    if password == passwd:
        root = assets+"/report.htm"
        print "Successful login to web UI"
        servefile(httpheader,conn,root)
    else:
        print "Failed login to web UI"
        mainlistener(httpheader,conn)

def logouthandler(httpheader,conn):
    mainlistener(httpheader,conn)

def server(HOST,PORT,passwd):
    lisfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    lisfd.bind((HOST, PORT))
    lisfd.listen(5)

    while 1:
        confd,addr = lisfd.accept()
        data = confd.recv(2048)
        if not data:
            break
        request = requestparse(data)
        method = request[0]
        root = request[1]
        protocol = request[2]
        httpheader = protocol+' '+'200'+' '+'OK'+'\n'
        if root == "/" or root == "/report.htm":
            httpheader = httpheader+"Context-Type: "+"text/html"+'\n'+"Server: Python-slp version 1.0\n"+"Context-Length: "
            mainlistener(httpheader,confd)
        elif root.find("/css/")!= -1 or root.find("/js/")!= -1:
            if root.find("/css/")!= -1:
                httpheader = httpheader+"Context-Type: "+"text/css"+'\n'+"Server: Python-slp version 1.0\n"+"Context-Length: "
                servefile(httpheader,confd,assets+root)
            else:
                httpheader = httpheader+"Context-Type: "+"application/x-javascript"+'\n'+"Server: Python-slp version 1.0\n"+"Context-Length: "
                servefile(httpheader,confd,assets+root)
        elif root.find("/api")!= -1:
            apihandler(confd)
        elif root == "/login":
            httpheader = httpheader+"Context-Type: "+"text/html"+'\n'+"Server: Python-slp version 1.0\n"+"Context-Length: "
            loginhandler(httpheader,confd,data,passwd)
        elif root == "/logout":
            httpheader = httpheader+"Context-Type: "+"text/html"+'\n'+"Server: Python-slp version 1.0\n"+"Context-Length: "
            logouthandler(httpheader,confd)
        confd.close()
