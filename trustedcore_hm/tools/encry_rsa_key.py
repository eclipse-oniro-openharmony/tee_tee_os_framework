#!/usr/bin/env python3
# encrypt rsa priv key
# Copyright Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.


import os
from  binascii import unhexlify
from  secrets  import token_bytes
from hashlib  import sha256
from Crypto.Cipher import AES
from Cryptodome.PublicKey import RSA


# Add key here, like "\x12\x23\x34"
G_OEM_KEY = b""


def aes_encrypt(key, iv, content):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypt_bytes = cipher.encrypt(content)
    return encrypt_bytes


def encrypt_rsa_key():
    rsa_key = RSA.import_key(open("KeyRsaPriv.pem").read())

    if os.path.exists("tz_encry_rsa.h"):
        os.remove("tz_encry_rsa.h")
    file = os.open("tz_encry_rsa.h", os.O_RDWR | os.O_CREAT, 0o644)
    iv = token_bytes(16)

    iv_str = "uint8_t wb_vec[16] = {\n"
    for i, element in enumerate(iv):
        iv_str = '{}{}, '.format(iv_str, hex(element))
        if i % 16 == 15:
            iv_str = '{}{}'.format(iv_str, '\n')
    iv_str = '{}{}'.format(iv_str, '};\n')
    os.write(file, iv_str.encode('utf-8'))

    if len(hex(rsa_key.n)) % 2 == 1:
        rsa_key_n = "{}{}".format("0", hex(rsa_key.n)[2:])
    else:
        rsa_key_n = hex(rsa_key.n)[2:]

    aes_key = sha256(G_OEM_KEY).hexdigest()
    encrypt_result = \
        aes_encrypt(unhexlify(aes_key), iv, unhexlify(rsa_key_n))

    n_str = "uint8_t wb_n_ptr[] = {\n"
    for i, element in enumerate(encrypt_result):
        n_str = '{}{}, '.format(n_str, hex(element))
        if i % 16 == 15:
            n_str = '{}{}'.format(n_str, '\n')
    n_str = '{}{}'.format(n_str, '};\n')

    os.write(file, n_str.encode('utf-8'))

    if len(hex(rsa_key.d)) % 2 == 1:
        rsa_key_d = "{}{}".format("0", hex(rsa_key.d)[2:])
    else:
        rsa_key_d = hex(rsa_key.d)[2:]

    encrypt_result = \
        aes_encrypt(unhexlify(aes_key), iv, unhexlify(rsa_key_d))
    d_str = "uint8_t wb_d_ptr[] = {\n"
    for i, element in enumerate(encrypt_result):
        d_str = '{}{}, '.format(d_str, hex(element))
        if i % 16 == 15:
            d_str = '{}{}'.format(d_str, '\n')
    d_str = '{}{}'.format(d_str, '};\n')

    os.write(file, d_str.encode('utf-8'))
    os.close(file)
    return


def main():
    encrypt_rsa_key()

if __name__ == '__main__':
    main()
