#!/usr/bin/python
#this script makes the initial configuration to use TLS with mosquitto
# it generates the mosquitto key pair and retrieves a certificate and CRL from CA
# if the configuration has already been done before, this script does nothing

import conf
import os
import requests, json
import binascii
from OpenSSL import crypto
import certUtils

def generateKeys():
    if os.path.isfile(conf.certsDir + 'mosquitto.key'):
        return

    certUtils.generatePrivateKey(conf.certsDir + "/mosquitto.key", conf.keyLength)

    print "mosquitto key pair created"


def generateCSR():
    if os.path.isfile(conf.certsDir + "/mosquitto.csr"):
        return

    certUtils.generateCSR(CName = 'mosquitto', 
                privateKeyFile = conf.certsDir + "/mosquitto.key", 
                csrFileName = conf.certsDir + "/mosquitto.csr",
                dnsname = ['mqtt', 'mosquitto', 'localhost'])


def askCertSign():
    if os.path.isfile(conf.certsDir + "/mosquitto.crt"):
        return
    passwd = binascii.b2a_hex(os.urandom(16))
    
    #create the ejbca user
    req = json.dumps( {
        "caName": conf.CAName,
        "certificateProfileName": "CFREE",
        "clearPwd": True,
        "endEntityProfileName": "EMPTY_CFREE",
        "keyRecoverable": False,
        "password": passwd,
        "sendNotification": False,
        "status": 10,
        "subjectDN": "CN=mosquitto",
        "tokenType": "USERGENERATED",
        "username": "mosquitto"
    } )

    try:
        response = requests.post(conf.EJBCA_API_URL + "/user",  headers=conf.defaultHeader, data = req)
    except requests.exceptions.ConnectionError:
        print "Can't connect to EJBCA REST service"
        exit(-1)
    
    if response.status_code == 200:
        print("EJBCA User created")        
    else:
        print("Cant create user. EJBCA-REST return code: " + str(response.status_code))
        print "content: " + str(response.content)
        exit(-1)
    
    with open(conf.certsDir + "/mosquitto.csr", "r") as csrFile:
        csr = csrFile.read()
    cutDownCLR = csr[csr.find('-----BEGIN CERTIFICATE REQUEST-----') + len('-----BEGIN CERTIFICATE REQUEST-----'):csr.find("-----END CERTIFICATE REQUEST-----")].replace("\n", "")

    req = json.dumps({
        "passwd": passwd,
        "certificate": cutDownCLR
    })
    
    try:
        response = requests.post(conf.EJBCA_API_URL + "/user/mosquitto/pkcs10",  headers=conf.defaultHeader, data = req)
    except requests.exceptions.ConnectionError:
        print "Can't connect to EJBCA REST service"
        exit(-1)
    
    if response.status_code == 200:
        print("mosquitto certificate signed")
        certUtils.saveCRT(conf.certsDir + "/mosquitto.crt", json.loads(response.content)['status']['data'])
    else:
        print("Cant sign the CRT. EJBCA-REST return code: " + str(response.status_code))
        print "content: " + str(response.content)
        exit(-1)
    

def retrieveCAChain():
    if os.path.isfile(conf.certsDir + "/ca.crt"):
        return

    try:
        response = requests.get(conf.EJBCA_API_URL + '/ca/'+ conf.CAName,  headers=conf.defaultHeader)
    except requests.exceptions.ConnectionError:
        print "Can't connect to EJBCA REST service"
        exit(-1)
    
    try:
        rawCrt = json.loads( response.content )['certificate']
    except KeyError:
        print "Invalid answer returned from EJBCA."
        exit(-1)
    
    certUtils.saveCRT(conf.certsDir + "/ca.crt",rawCrt)
    print("CA certificates retrieved")

def retrieveCRL():
    try:
        response = requests.get(conf.EJBCA_API_URL + '/ca/'+ conf.CAName + "/crl",  headers=conf.defaultHeader)
    except requests.exceptions.ConnectionError:
        print "Can't connect to EJBCA REST service"
        exit(-1)
    
    try:
        rawCRL = json.loads( response.content )['CRL']
    except KeyError:
        print "Invalid answer returned from EJBCA."
        exit(-1)
    
    try:
        certUtils.saveCRL(conf.certsDir + "/ca.crl", rawCRL)
    except crypto.Error:
        print("Could not decode retrieved CRL")

if __name__ == '__main__':
    retrieveCAChain()
    generateKeys()
    generateCSR()
    askCertSign()
    retrieveCRL()
    exit(0)

