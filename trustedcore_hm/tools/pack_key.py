#!/usr/bin/env python3
# trustedcore pack key to header
# Copyright Huawei Technologies Co., Ltd. 2010-2021. All rights reserved.

import struct

from binascii import unhexlify
from pathlib import Path

from Cryptodome.PublicKey import RSA


ca_rsa_header_offset = 36
ta_rsa_header_offset = ca_rsa_header_offset + 12
ta_root_cert_offset = ta_rsa_header_offset + 12
ta_config_cert_offset = ta_root_cert_offset + 12
ta_ecies_header_offset = ta_config_cert_offset + 12
ca_rsa_magic = 0x5a5aa501
ta_rsa_magic = 0x5a5aa502
ta_cert_magic = 0x5a5aa503
ta_config_magic = 0x5a5aa504
ta_ecies_magic = 0x5a5aa505
ca_path = "ca_public_key.pem"
ta_path = "ta_public_key.pem"
ta_root_cert_path = "huawei_it_product.cer"
ta_config_cert_path = "public_config_key.der"
ecies_path = "ecies.bin"
tee_image_path = "trustedcore.img"


def add_pub_key_to_header(image_path, rsa_key_path_name, header_offset, magic):
    if Path(rsa_key_path_name).is_file():
        print("parse:", rsa_key_path_name)
    else:
        print("file not exist", rsa_key_path_name)
        return

    header = 0
    file = open(image_path, "rb+")
    print("file name:", file.name)
    file.seek(0, 0)
    header_str = file.read(36)
    header = struct.unpack('9I',  header_str)
    header_size = header[0]
    rsa_file = open(rsa_key_path_name, "rb")
    pubkey = RSA.import_key(rsa_file.read())

    e_len = 4
    e_max_len = 1024
    n_len = pubkey.size_in_bytes()
    n_max_len = 1024
    align_str = b'\0' * (e_max_len - e_len)

    if len(hex(pubkey.e)[2:]) < e_len * 2:
        e_str = hex(pubkey.e)[2:].rjust(e_len * 2, "0")

    if len(hex(pubkey.n)[2:]) < n_max_len * 2:
        n_str = hex(pubkey.n)[2:].rjust(n_len * 2, "0")
        n_str_1 = n_str.ljust(n_max_len * 2, "0")
    else:
        n_str_1 = hex(pubkey.n)[2:]

    file.seek(0, 0)
    img_str = file.read()
    tmp_str = unhexlify(e_str)[::-1] + \
    align_str + \
    struct.pack("<I", (len(hex(pubkey.e)[2:]) + 1) // 2) + \
    unhexlify(n_str_1) + \
    struct.pack("<I", (len(hex(pubkey.n)[2:]) + 1) // 2)

    file.seek(0, 0)
    new_str = img_str[0:header_size] + tmp_str + img_str[header_size:]
    file.write(new_str)
    rsa_len = len(tmp_str)
    header_size += rsa_len
    file.seek(0, 0)

    #update header size
    buffer = struct.pack('1I', header_size)
    file.write(buffer)

    #rsa tags
    rsa_magic = magic
    rsa_offset = header_size - rsa_len
    rsa_size = rsa_len
    tag_str = struct.pack('3I', rsa_magic, rsa_offset, rsa_size)
    file.seek(header_offset, 0)
    file.write(tag_str)
    file.close()
    return


def add_cert_pub_to_header(image_path, cert_path_name, header_offset, magic):

    if Path(cert_path_name).is_file():
        print("parse:", cert_path_name)
    else:
        print("file not exist", cert_path_name)
        return

    header = 0
    file = open(image_path, "rb+")
    print("file name:", file.name)
    file.seek(0, 0)
    header_str = file.read(36)
    header = struct.unpack('9I', header_str)
    header_size = header[0]
    rsa_file = open(cert_path_name, "rb")
    pubkey = RSA.import_key(rsa_file.read())
    derkey = pubkey.exportKey(format="DER")

    file.seek(0, 0)
    img_str = file.read()

    file.seek(0, 0)
    rsa_len = len(derkey)
    len_buffer = struct.pack('1I', rsa_len)
    rsa_size = rsa_len + len(len_buffer)
    new_str = img_str[0:header_size] + \
              len_buffer + \
              derkey + \
              img_str[header_size:]

    file.write(new_str)
    header_size = header_size + rsa_size
    file.seek(0, 0)

    #update header size
    buffer = struct.pack('1I', header_size)
    print(buffer)
    file.write(buffer)

    #rsa tags
    rsa_magic = magic
    rsa_offset = header_size - rsa_size
    tag_str = struct.pack('3I', rsa_magic, rsa_offset, rsa_size)
    print(tag_str)
    file.seek(header_offset, 0)
    file.write(tag_str)
    file.close()
    return


def add_ta_loadkey_to_header(image_path, ecies_path_name, header_offset, magic):

    if Path(ecies_path_name).is_file():
        print("parse:", ecies_path_name)
    else:
        print("file not exist", ecies_path_name)
        return

    header = 0
    file = open(image_path, "rb+")
    print("file name:", file.name)
    file.seek(0, 0)
    header_str = file.read(36)
    header = struct.unpack('9I', header_str)
    header_size = header[0]
    print("ecise new header:", header_size)

    ecies_file = open(ecies_path_name, "rb+")
    ecies_file.seek(0, 0)
    file.seek(0, 0)
    img_str = file.read()
    ecies_str = ecies_file.read()
    ecies_len = len(ecies_str)
    print("ecies len:", ecies_len)

    file.seek(0, 0)
    new_str = img_str[0:header_size] + ecies_str + img_str[header_size:]
    file.write(new_str)

    header_size += ecies_len
    file.seek(0, 0)

    print("ecies add header size:", header_size)
    #update header size
    buffer = struct.pack('1I', header_size)
    print(buffer)
    file.write(buffer)

    #ecise tags
    ecise_magic = magic
    ecies_offset = header_size - ecies_len
    tag_str = struct.pack('3I', ecise_magic, ecies_offset, ecies_len)
    print(tag_str)
    file.seek(header_offset, 0)
    file.write(tag_str)
    file.close()
    return


def align_header(tee_path):

    header = 0
    file = open(tee_path, "rb+")
    print("file name:", file.name)
    file.seek(0, 0)
    header_str = file.read(4)
    header = struct.unpack('I', header_str)
    header_size = header[0]
    print(header_size)

    mod = header_size % 64
    align_str = b'\0' * (64 -  mod)
    print(align_str)

    file.seek(0, 0)
    img_str = file.read()

    file.seek(0, 0)
    new_str = img_str[0:header_size] + align_str + img_str[header_size:]
    file.write(new_str)

    header_size += (64 - mod)
    file.seek(0, 0)

    print("new header size:", header_size)
    #update header size
    buffer = struct.pack('1I', header_size)
    print(buffer)
    file.write(buffer)
    return
