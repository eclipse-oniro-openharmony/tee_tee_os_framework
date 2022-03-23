#!/usr/bin/env python3
# generate a ecc pub from oem key
# Copyright Huawei Technologies Co., Ltd. 2010-2021. All rights reserved.

import os

from binascii import unhexlify, hexlify
from hashlib  import sha256

from Cryptodome.PublicKey import ECC
from Cryptodome.Util.py3compat import bord, tobytes, b, tostr, bchr


def generate_ecc_pub(oem_key):

    o_key = unhexlify(oem_key)
    d = int(sha256(o_key).hexdigest(), 16)

    key = ECC.EccKey(curve="P-256", d=d)
    priv_fd = os.open("private.pem",  os.O_RDWR | os.O_CREAT, 0o644)
    os.write(priv_fd, (key.export_key(format="PEM") + "\n").encode('utf-8'))

    pub_fd = os.open("public.pem",  os.O_RDWR | os.O_CREAT, 0o644)
    pub_str = key.public_key().export_key(format="PEM") + "\n"
    os.write(pub_fd, pub_str.encode('utf-8'))

    fd = open("public.pem", "rb")
    key = ECC.import_key(fd.read())
    ecc_bin = os.open("ecc_pub.bin", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(ecc_bin, bchr(4))
    os.write(ecc_bin, key.pointQ.x.to_bytes())
    os.write(ecc_bin, key.pointQ.y.to_bytes())

    ecc_pub = os.open("ecc_pub.txt", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(ecc_pub, hexlify(bchr(4)))
    os.write(ecc_pub, hexlify(key.pointQ.x.to_bytes()))
    os.write(ecc_pub, hexlify(key.pointQ.y.to_bytes()))

    os.close(priv_fd)
    os.close(pub_fd)
    os.close(ecc_bin)
    os.close(ecc_pub)
    fd.close()
    return

g_key = b''  # add key value here
generate_ecc_pub(g_key)
