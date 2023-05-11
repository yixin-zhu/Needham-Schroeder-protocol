"""
Helper functions for AES encryption.
"""
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from random import randint, choices
from string import ascii_letters, digits


def generate_key():
    """() -> bytes

    Generates a key for symmetric encryption and decryption.
    """
    key = ''.join(choices(ascii_letters + digits, k=16))
    key = bytes(key, "utf-8")
    return key


def encrypt(key, plaintext):
    """(bytes, str) -> bytes

    Encrypts a plaintext string to a sequence of Base64 bytes using key.

    :key: AES key to encrypt with
    :plaintext: plaintext string to encrypt
    """
    iv = b'1234567890ZYXWVU'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad = '\x00' * ((16 - len(plaintext)) % 16)
    plaintext = bytes(plaintext + pad, "utf-8")
    ciphertext = cipher.encrypt(plaintext)
    return b64encode(ciphertext)


def decrypt(key, ciphertext):
    """(bytes, bytes) -> str

    Decrypts a sequence of Base64 bytes using key.

    :key: AES key to decrypt with
    :ciphertext: ciphertext bytes to decrypt
    """
    iv = b'1234567890ZYXWVU'
    ciphertext = b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = plaintext.rstrip(b'\x00')
    return plaintext.decode("utf-8")
