"""
Helper functions for Needham-Schroeder protocol.
"""
from socket import socket, AF_INET, SOCK_STREAM
from random import randint
from helpers import rsa


def generate_nonce(length=8):
    """(int) -> int

    Generates and returns a pseudorandom number of a fixed given length.

    :length: number of digits to be generated
    """
    return int(''.join(str(randint(0, 9)) for i in range(length)))


def get_public_key(pks_address, host, recipient, recip_key):
    """(tuple of (str, int), str, str, RsaKey) -> bytes

    Communicates with the public key server to get the RSA public key of the given host.
    Requires that the public key server is already running.

    :pks_address: address of the public key server
    :host: name of the host to get RSA public key of
    :recipient: name of the host to recieve the public key
    """
    # connect to PKS, get public key of given host name
    key_and_host = None
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect(pks_address)
        request = bytes("{},{}".format(recipient, host), "utf-8")
        sock.sendall(request)
        response = sock.recv(1024)
        # parse and decrypt response
        key_and_host = rsa.big_decrypt(recip_key, response.split(b','))
    # parse and convert to get public key
    public_key = key_and_host[:key_and_host.rfind(',')]
    return bytes(public_key, "utf-8")
