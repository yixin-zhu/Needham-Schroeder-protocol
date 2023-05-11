from helpers import rsa
from helpers import aes
from helpers import ns


# connection for public key server
PKI_HOST = '127.0.0.1'
PKI_PORT = 65432

# connection for Server
SERVER_HOST = '127.0.0.2'
SERVER_PORT = 65433

# connection for Mallory
ADV_HOST = '127.0.0.3'
ADV_PORT = 65434

# signals
RESP_VERIFIED = 200
RESP_DENIED = 401
SIG_START = '419'
SIG_GOOD = '420'
SIG_BAD = '421'
SIG_END = '422'

# modes of file transfer
UPLOAD = 'u'
DOWNLOAD = 'd'
