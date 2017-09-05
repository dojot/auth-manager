#!/usr/bin/python
#this script make the initial configuration to use TLS with mqtt
# it generate the mosquitto key pair and retrieve a certificate and CRL from CA
# if the configuration has already done before, this script does nothing

import conf
import os
import requests, json
import re
import binascii
from OpenSSL import crypto

def generateKeys():
    if os.path.isfile(conf.certsDir + 'mosquitto.key'):
        return

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, conf.keyLength)
    with open(conf.certsDir + "/mosquitto.key", "w") as keyFile:
        keyFile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    print "mosquitto key pair created"

#based on https://github.com/cjcotton/python-csr
def generateCSR():
    if os.path.isfile(conf.certsDir + "/mosquitto.csr"):
        return

    req = crypto.X509Req()
    req.get_subject().CN = 'mosquitto'

    # Add in extensions
    base_constraints = ([
        crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
    ])
    x509_extensions = base_constraints

    san_constraint = crypto.X509Extension("subjectAltName", False, 'DNS: mqtt, DNS: localhost')
    x509_extensions.append(san_constraint)
    req.add_extensions(x509_extensions)
    
    with open(conf.certsDir + "/mosquitto.key") as keyfile:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, keyfile.read())

    req.set_pubkey(key)
    req.sign(key, "sha256")

    with open(conf.certsDir + "/mosquitto.csr", "w") as csrFile:
        csrFile.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)) 

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
        cert = "-----BEGIN CERTIFICATE-----\n" +  json.loads(response.content)['status']['data']  + "\n-----END CERTIFICATE-----\n"
        with open(conf.certsDir + "/mosquitto.crt", "w") as certFile:
            certFile.write(cert)
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
        rawCrt = json.loads( response.content )['status'][0]['certificateData']
    except KeyError:
        print "Invalid answer returned from EJBCA."
        exit(-1)
    
    caCrt = "-----BEGIN CERTIFICATE-----\n" +  rawCrt  + "\n-----END CERTIFICATE-----\n"
    
    with open(conf.certsDir + "/ca.crt", "w") as crlFile:
        crlFile.write(caCrt)
    print("CA certificates retrieved")

def retrieveCRL():
    try:
        response = requests.get(conf.EJBCA_API_URL + '/ca/'+ conf.CAName + "/crl",  headers=conf.defaultHeader)
    except requests.exceptions.ConnectionError:
        print "Can't connect to EJBCA REST service"
        exit(-1)
    
    try:
        rawCrl = json.loads( response.content )['CRL']
    except KeyError:
        print "Invalid answer returned from EJBCA."
        exit(-1)
    
    crl = "-----BEGIN X509 CRL-----\n" + re.sub("(.{64})", "\\1\n", rawCrl, 0, re.DOTALL)  + "\n-----END X509 CRL-----\n"
    try:
        crypto.load_crl(crypto.FILETYPE_PEM, crl)
    except crypto.Error:
        return False

    with open(conf.certsDir + "/ca.crl", "w") as crlFile:
        crlFile.write(crl)
    print("CRL retrieved")

if __name__ == '__main__':
    retrieveCAChain()
    generateKeys()
    generateCSR()
    askCertSign()
    retrieveCRL()
    exit(0)

