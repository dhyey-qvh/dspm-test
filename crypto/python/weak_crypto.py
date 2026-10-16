"""Intentionally insecure scan fixtures. Never use these functions in an application."""

import hashlib
import random

from Crypto.Cipher import AES, ARC4, DES, DES3
from Crypto.PublicKey import RSA


def legacy_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def legacy_signature(payload):
    return hashlib.sha1(payload).hexdigest()


def des_encrypt(block):
    return DES.new(b"12345678", DES.MODE_ECB).encrypt(block)


def triple_des_encrypt(block):
    return DES3.new(b"12345678abcdefghABCDEFGH", DES3.MODE_ECB).encrypt(block)


def rc4_encrypt(payload):
    return ARC4.new(b"synthetic-demo-key").encrypt(payload)


def aes_ecb_encrypt(block):
    return AES.new(b"0123456789abcdef", AES.MODE_ECB).encrypt(block)


def aes_fixed_iv_encrypt(block):
    return AES.new(b"0123456789abcdef", AES.MODE_CBC, iv=b"0000000000000000").encrypt(block)


def small_rsa_key():
    return RSA.generate(1024)


def weak_password_derivation(password):
    return hashlib.pbkdf2_hmac("sha1", password.encode(), b"fixed-salt", 100)


def predictable_reset_token():
    return str(random.randint(100000, 999999))
