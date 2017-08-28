#!/usr/bin/python
import json, requests
import OpenSSL
import re
import os

from flask import Flask
from flask import request
from flask import make_response as fmake_response

#TODO: move this to a configuration file
defaultHeader = {'content-type':'application/json', 'Accept': 'application/json'}
CAName = "DUMMY"
ACLfilePath = "access.acl"

app = Flask(__name__)
# CORS(app)
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

    elif requestData['action'] == 'crl':
        return updateCRL()
    
    else:
        return formatResponse(400, "'Action' " + requestData['action'] + " not implemented")

def updateCRL():
    try:
        response = requests.get("http://localhost:5000/ca/" + CAName + "/crl",  headers=defaultHeader)
    except requests.exceptions.ConnectionError:
        return formatResponse(503,"Can't connect to EJBCA REST service.")
    try:
        newCRL = json.loads( response.content )['CRL']
        if processCRL(newCRL):
            return formatResponse(200)
        else:
            return formatResponse(500, "The CRL returned by EJBCA could not be decoded")
    except KeyError:
        return formatResponse(500,"Invalid answer returned from EJBCA.")
    

#receve a PEM CRL. If its valid, save to file
def processCRL(rawCrl):
    crl = "-----BEGIN X509 CRL-----\n" + re.sub("(.{64})", "\\1\n", rawCrl, 0, re.DOTALL)  + "\n-----END X509 CRL-----\n"
    
    try:
        crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl)
    except OpenSSL.crypto.Error:
        return False

    #list the revoked certificate serial numbers
    #TODO: remove revoked devices from the ACL?
    #for rvk in crl_object.get_revoked():
    #    print "Serial:", rvk.get_serial()

    crlFile = open(CAName + ".crl","w")
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
    crlFile = open(ACLfilePath,"a")

    #user can write on
    crlFile.write("user " + deviceName )
    crlFile.write("\ntopic write " + topic)
    crlFile.write("\n")

    crlFile.close()
    return formatResponse(200)

#remove a device from ACL file
#return True if the device was removed, return false otherwise
def removeDeviceACL(deviceName):
    userfound = False

    try:
        crlFile = open(ACLfilePath,"r")
    except IOError:
        return False
    newCrlFile =  open(ACLfilePath + ".tmp","w")
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
        os.remove(ACLfilePath + ".tmp")
        return False

    os.remove(ACLfilePath)
    os.rename(ACLfilePath + ".tmp",ACLfilePath)
    return True

def removeDeviceACLRequest(requestData):
    if 'device' not in requestData.keys():
        return formatResponse(400, "missing device name")

    deviceName = requestData['device']
    if removeDeviceACL(deviceName):
        return formatResponse(200, "Device " + deviceName + " removed from ACL")
    else:
        return formatResponse(404, "No device with name " + deviceName + " found in ACL")      

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int("9010"), threaded=True)
    
