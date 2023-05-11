"""
Helper functions for RSA encryption.
"""
from base64 import b64decode, b64encode
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_key():
    """() -> RsaKey

    Generates an 1024-bit RSA key object with a public-private key pair.
    """
    random_generator = Random.new().read
    rsa_key = RSA.generate(1024, random_generator)
    return rsa_key


def export_key(rsa_key, file_name):
    """(RsaKey, str) -> NoneType

    Exports and saves the private key to a file with the given name.

    :rsa_key: RSA key pair to export and same
    :file_name: name of file to save RSA key pair to
    """
    export = rsa_key.exportKey()
    with open(file_name, "wb") as outputStream:
        outputStream.write(export)


def import_key(byteStream):
    """(bytes or str) -> RsaKey

    Imports and returns the RSA key pair.

    :byteStream: RSA key or name of file containing RSA key pair
    """
    content = None
    if isinstance(byteStream, bytes):
        content = byteStream
    else:
        with open(byteStream, "rb") as inputStream:
            content = inputStream.read()
    rsa_key = RSA.importKey(content)
    return rsa_key


def export_public_key(rsa_key):
    """(RsaKey) -> bytes

    Exports and returns the RSA public key.

    :rsa_key: RSA key pair to get the public key from
    """
    public_key = rsa_key.publickey()
    export = public_key.exportKey()
    return export


def encrypt(rsa_key, plaintext):
    """(RsaKey, str) -> bytes

    Encrypts ASCII plaintext string into Base64 bytes.

    :rsa_key: RSA key pair, or RSA public key, to encrypt to plaintext.
    :plaintext: plaintext string to encrypt
    """
    cipher = PKCS1_OAEP.new(rsa_key.publickey())
    plaintext = bytes(plaintext, "utf-8")
    ciphertext = cipher.encrypt(plaintext)
    return b64encode(ciphertext)


def big_encrypt(rsa_key, plaintext):
    """(RsaKey, str) -> list of bytes

    Encrypts ASCII plaintext string into a list of Base64 bytes plaintext, if plaintext is longer
    than 64 characters.

    :rsa_key: RSA key pair, or RSA public key, to encrypt from plaintext
    :plaintext: plaintext string to encrypt
    """
    length = 64
    chunks = (plaintext[0+i:length+i] for i in range(0, len(plaintext), length))
    cipherchunks = [encrypt(rsa_key, chunk) for chunk in chunks]
    return cipherchunks


def decrypt(rsa_key, ciphertext):
    """(RsaKey, bytes) -> str

    Decrypts Base64 bytes into ASCII plaintext string.

    :rsa_key: RSA key pair to decrypt the ciphertext
    :ciphertext: Base64 ciphertext string to decrypt
    """
    ciphertext = b64decode(ciphertext)
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode("utf-8")


def big_decrypt(rsa_key, cipherchunks):
    """(RsaKey, list of bytes) -> str

    Decrypts a list of Base64 bytes into ASCII plaintext string, if original plaintext is longer than 64 characters.

    :rsa_key: RSA key pair to decrypt the ciphertext
    :cipherchunks: list of Base64 ciphertext strings to decrypt
    """
    plaintext = ''.join(decrypt(rsa_key, chunk) for chunk in cipherchunks)
    return plaintext
