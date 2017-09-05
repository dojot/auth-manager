#!/usr/bin/python
import json, requests
import OpenSSL
import re
import os
import signal

from flask import Flask
from flask import request
from flask import make_response as fmake_response

import conf

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
        try:
            updateCRL()
        except requests.exceptions.ConnectionError:
            return formatResponse(503,"Can't connect to EJBCA REST service.")
        except KeyError:
            return formatResponse(500,"Invalid answer returned from EJBCA.")
        except ValueError as err:
            return formatResponse(500,err.message)

        return removeDeviceACLRequest(requestData)
    else:
        return formatResponse(400, "'Action' " + requestData['action'] + " not implemented")

def updateCRL():
    response = requests.get(conf.EJBCA_API_URL + '/ca/' + conf.CAName + "/crl",  headers=conf.defaultHeader)
    newCRL = json.loads( response.content )['CRL']
    if processCRL(newCRL):
        return True
    else:
        raise ValueError('The CRL returned by EJBCA could not be decoded')    
    

#receve a PEM CRL. If its valid, save to file crl
def processCRL(rawCrl):
    crl = "-----BEGIN X509 CRL-----\n" + re.sub("(.{64})", "\\1\n", rawCrl, 0, re.DOTALL)  + "\n-----END X509 CRL-----\n"
    
    try:
        crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl)
    except OpenSSL.crypto.Error:
        return False
    
    crlFile = open(conf.certsDir + conf.CAName + ".crl","w")
    crlFile.write(crl)
    crlFile.close()
    return True

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
    crlFile = open(conf.ACLfilePath,"a")

    #user can write on
    crlFile.write("user " + deviceName )
    crlFile.write("\ntopic write " + topic)
    crlFile.write("\n")

    crlFile.close()
    reloadMosquittoConf()
    return formatResponse(200)

#remove a device from ACL file
#return True if the device was removed, return false otherwise
def removeDeviceACL(deviceName):
    userfound = False

    try:
        crlFile = open(conf.ACLfilePath,"r")
    except IOError:
        return False
    newCrlFile =  open(conf.ACLfilePath + ".tmp","w")
    for line in crlFile:
        if deviceName not in line:
            newCrlFile.write(line)
        else:
            #skip the line and the next one
            line2 = crlFile.next()
            userfound = True
    crlFile.close()
    newCrlFile.close()
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
        reloadMosquittoConf()
        return formatResponse(200, "Device " + deviceName + " removed from ACL")
    else:
        return formatResponse(404, "No device with name " + deviceName + " found in ACL")      

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(conf.APIport), threaded=True)
    
