#!/usr/bin/python
import json, requests
import OpenSSL
import os
import signal

from flask import Flask
from flask import request
from flask import make_response as fmake_response

import conf
import certUtils

app = Flask(__name__)
app.url_map.strict_slashes = False

def make_response(payload, status):
    resp = fmake_response(payload, status)
    resp.headers['content-type'] = 'application/json'
    return resp

def formatResponse(status, message=None):
    payload = None
    if message:
        payload = json.dumps({ 'message': message, 'status': status})
    elif status >= 200 and status < 300:
        payload = json.dumps({ 'message': 'ok', 'status': status})
    else:
        payload = json.dumps({ 'message': 'Request failed', 'status': status})
    return make_response(payload, status)

def reloadMosquittoConf():
    f = open(conf.mosquittoPIDfile,"r")
    os.kill( int(f.readline()) , signal.SIGHUP)
    f.close()
     

@app.route('/notifyDeviceChange', methods=['POST'])
def notifyDeviceChange():
    try:
        requestData = json.loads(request.data)
    except ValueError:
        return formatResponse(400, 'malformed JSON')

    if 'action' not in requestData.keys():
        return formatResponse(400, "'Action' not specified ")

    if requestData['action'] in ['create','update']:
        return addDeviceACLRequest(requestData)

    elif requestData['action'] == 'delete':
        return removeDeviceACLRequest(requestData)

    else:
        return formatResponse(400, "'Action' " + requestData['action'] + " not implemented")

#receve a PEM CRL. If its valid, save to file
@app.route('/crlupdate', methods=['POST'])
def updateCRL():
    try:
        requestData = json.loads(request.data)
    except ValueError:
        return formatResponse(400, 'malformed JSON')

    if 'crl' not in requestData.keys():
        return formatResponse(400, "missing crl")
    
    try:
        certUtils.saveCRL(conf.certsDir + conf.CAName + ".crl", requestData['crl'])
        reloadMosquittoConf()
        return formatResponse(200)
    except OpenSSL.crypto.Error:
        return formatResponse(400, "PEM formated CRL could not be decoded")

#add or update device
def addDeviceACLRequest(requestData):
    if 'device' not in requestData.keys():
        return formatResponse(400, "missing device name")

    if 'topic' not in requestData.keys():
        return formatResponse(400, "missing device topic")

    deviceName = requestData['device']
    
    #remove the old device
    if requestData['action'] == 'update':
        if not removeDeviceACL(deviceName):
            return formatResponse(404, "No device with name " + deviceName + " found in ACL")
    
    topic = requestData['topic']
    
    #TODO: check if user aready exist?
    aclFile = open(conf.ACLfilePath,"a")

    #user can write on
    aclFile.write("user " + deviceName )
    aclFile.write("\ntopic write " + topic)
    aclFile.write("\n")

    aclFile.close()
    reloadMosquittoConf()
    return formatResponse(200)

#remove a device from ACL file
#return True if the device was removed, return false otherwise
def removeDeviceACL(deviceName):
    userfound = False

    try:
        aclFile = open(conf.ACLfilePath,"r")
    except IOError:
        return False
    newaclFile =  open(conf.ACLfilePath + ".tmp","w")
    for line in aclFile:
        if deviceName not in line:
            newaclFile.write(line)
        else:
            #skip the line and the next one
            line2 = aclFile.next()
            userfound = True
    aclFile.close()
    newaclFile.close()
    if not userfound:
        os.remove(conf.ACLfilePath + ".tmp")
        return False

    os.remove(conf.ACLfilePath)
    os.rename(conf.ACLfilePath + ".tmp",conf.ACLfilePath)
    return True

def removeDeviceACLRequest(requestData):
    if 'device' not in requestData.keys():
        return formatResponse(400, "missing device name")

    deviceName = requestData['device']
    if removeDeviceACL(deviceName):
        try:
            if 'crl' in requestData.keys():
                certUtils.saveCRL(conf.certsDir + "/ca.crl", requestData['crl'])
        except OpenSSL.crypto.Error:
            return formatResponse(400, "PEM formated CRL could not be decoded")

        reloadMosquittoConf()
        return formatResponse(200, "Device " + deviceName + " removed from ACL")
    else:
        return formatResponse(404, "No device with name " + deviceName + " found in ACL")      

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(conf.APIport), threaded=True)
    
