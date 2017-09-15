#configuration file
import os

APIport = 9010

try:
    EJBCA_API_URL = os.environ['EJBCA_API_URL']
except KeyError:
    EJBCA_API_URL = "http://ejbca:5583"

try:
    CAName = os.environ['CA_NAME']
except KeyError:
    CAName = "IOTmidCA"

try:
    keyLength = int(os.environ['KEY_LENGTH'])
except KeyError:
    keyLength = 2048

ACLfilePath = "/usr/local/src/mosquitto-1.4.13/certs/access.acl"
certsDir = "/usr/local/src/mosquitto-1.4.13/certs/"

mosquittoPIDfile = '/usr/local/src/mosquitto-1.4.13/mosquitto.pid'


