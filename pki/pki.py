from socket import socket, AF_INET, SOCK_STREAM
import sys, os
sys.path.insert(1, os.path.join(sys.path[0], ".."))
from helpers import *



NAME = "pki"


def extract():
    """() -> NoneType
    Opens the public key infrastructure server to extract RSA public keys.
    The public keys must have already been in the server's folder.
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.bind((PKI_HOST, PKI_PORT))
        while True:
            sock.listen()
            conn, addr = sock.accept()
            with conn:
                print("PKI: connection from address", addr)
                while True:
                    # WRITE YOUR CODE HERE!
                    # A, B --->
                    request = conn.recv(1024)
                    if not request:
                        break
                    print("PKI: request is", request.decode())
                    recipient_and_host = request.decode().split(",")
                    recipient_name, host_name = recipient_and_host
                    print("PKI: received request for public key of " + host_name + " from " + recipient_name)

                    recipient_public_key = rsa.import_key("../" + NAME + "/" + recipient_name + ".asc")
                    host_public_key = rsa.import_key("../" + NAME + "/" + host_name + ".asc")

                    # <--- {K_PB, B}(K_PA)
                    host_public_key_str = rsa.export_public_key(host_public_key).decode()
                    response = "{},{}".format(host_public_key_str, host_name)
                    cipherchunks = rsa.big_encrypt(recipient_public_key, response)

                    back_message = b','.join(cipherchunks)
                    conn.sendall(back_message)
                    print("PKI: sent public key of " + host_name + " to " + recipient_name)


if __name__ == "__main__":
    print("PKI: I am the Public Key Infrastructure Server!")
    print("PKI: listening for a key to be extracted")
    extract()
