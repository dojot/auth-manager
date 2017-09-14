import re
from OpenSSL import crypto

#may cause crypto.Error

def saveCRL(filename, rawCRL):
    crl = "-----BEGIN X509 CRL-----\n" + re.sub("(.{64})", "\\1\n", rawCRL, 0, re.DOTALL)  + "\n-----END X509 CRL-----\n"    
    crypto.load_crl(crypto.FILETYPE_PEM, crl)    

    with open(filename, "w") as crlFile:
        crlFile.write(crl)

def saveCRT(filename, rawCRT):
    crt = "-----BEGIN CERTIFICATE-----\n" +  rawCRT  + "\n-----END CERTIFICATE-----\n"
    
    with open(filename, "w") as crtFile:
        crtFile.write(crt)


def generateCSR(CName, privateKeyFile, csrFileName, dnsname = [], ipaddr = []):
    #based on https://github.com/cjcotton/python-csr 
    ss = []
    for i in dnsname:
        ss.append("DNS: %s" % i)
    for i in ipaddr:
        ss.append("IP: %s" % i)
    ss = ", ".join(ss)
    
    
    req = crypto.X509Req()
    req.get_subject().CN = CName

    # Add in extensions
    base_constraints = ([
        crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
    ])
    x509_extensions = base_constraints    

    if ss:
        san_constraint = crypto.X509Extension("subjectAltName", False, ss)
        x509_extensions.append(san_constraint)
    
    req.add_extensions(x509_extensions)
    
    with open(privateKeyFile) as keyfile:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, keyfile.read())

    req.set_pubkey(key)
    req.sign(key, "sha256")

    with open(csrFileName, "w") as csrFile:
        csrFile.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)) 

def generatePrivateKey(keyFile, bitLen):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bitLen)
    with open(keyFile, "w") as keyFile:
        keyFile.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))