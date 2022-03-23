#!/usr/bin/env python3
# encrypt image generator
# Copyright Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

from __future__ import print_function
import struct
import os
import shutil
from  secrets  import token_bytes
from Crypto.Cipher import AES
from Cryptodome.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

RSA_PUB_FILE = "KeyRsaPub.pem"
IMAGE_FILE = "trustedcore.img"
TEMP_ENCRY_IMAGE_PATH = os.path.join(os.getcwd(), 'tmp_enc/')


def aes_encrypt(key, iv, content):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypt_bytes = cipher.encrypt(content)
    return encrypt_bytes


def encrypt_aes_key(pubkey_path, in_data, out_path):
    pubkey = RSA.importKey(open(pubkey_path).read())
    cipher = PKCS1_OAEP.new(pubkey)
    ciphertext = cipher.encrypt(in_data)

    out_file_fp = os.open(out_path, os.O_RDWR | os.O_CREAT, 0o644)
    os.write(out_file_fp, ciphertext)
    os.close(out_file_fp)
    return


def align_image(img_name):
    img_size = os.path.getsize(img_name)
    print("The size of image file is {0}".format(img_size))

    mod = img_size % 64
    if mod:
        img_size += 64 - mod

    img = os.open(img_name, os.O_RDWR | os.O_CREAT, 0o644)
    os.lseek(img, 0, 2)
    os.ftruncate(img, img_size)
    os.close(img)

    img_size = os.path.getsize(img_name)
    print("After align, the size of image file is {0}".format(img_size))
    return


def gen_enc_key_iv(key, iv):
    print("step 2: generate En_Krnd/IV")
    # pack Krnd and KrndIV to one file
    aes_key_iv = key + iv
    enc_rnd_file = os.path.join(TEMP_ENCRY_IMAGE_PATH, 'krnd.all.sec')
    encrypt_aes_key(RSA_PUB_FILE, aes_key_iv, enc_rnd_file)

    #add En_Krnd/IV to trustedcore_enc_header.bin
    enc_img_header_file = os.path.join(TEMP_ENCRY_IMAGE_PATH,\
        'trustedcore_enc_header.bin')

    encrnd_file_size = os.path.getsize(enc_rnd_file)
    encrnd_fp = open(enc_rnd_file, 'rb')
    enc_rnd_str = encrnd_fp.read(encrnd_file_size)
    encrnd_fp.close()

    img_magic_num = 0x5A5AA5A5
    img_format_version = 0x101
    img_reverse = [0, 0, 0, 0, 0]
    rsa_key_size = RSA.importKey(open(RSA_PUB_FILE).read()).size_in_bytes()
    header_info = struct.pack('<8I512s',
                    img_magic_num,
                    img_format_version,
                    rsa_key_size,
                    img_reverse[0],
                    img_reverse[1],
                    img_reverse[2],
                    img_reverse[3],
                    img_reverse[4],
                    enc_rnd_str)
    enc_img_head_fp = \
        os.open(enc_img_header_file, os.O_RDWR | os.O_CREAT, 0o644)
    os.write(enc_img_head_fp, header_info)
    os.close(enc_img_head_fp)
    return


def gen_enc_image(img_name):
    if os.path.exists(TEMP_ENCRY_IMAGE_PATH):
        shutil.rmtree(TEMP_ENCRY_IMAGE_PATH)
    os.mkdir(TEMP_ENCRY_IMAGE_PATH)

    #=== step 1: generate Krnd/IV, used to encrypimage
    print("step 1: generate Krnd/IV")
    aes_key = token_bytes(32)
    aes_iv = token_bytes(16)
    with open(img_name, 'rb') as in_file:
        img_data = in_file.read()
    image_size = os.path.getsize(img_name)
    padding = 16 - image_size % 16
    img_data += bytes([padding]) * padding
    encry_image_data = aes_encrypt(aes_key, aes_iv, img_data)

    #generate enc image
    enc_img_file = os.path.join(TEMP_ENCRY_IMAGE_PATH, 'trustedcore_enc.img')
    enc_img_fp = os.open(enc_img_file, os.O_RDWR | os.O_CREAT, 0o644)
    os.write(enc_img_fp, encry_image_data)
    os.close(enc_img_fp)

    #generate enc key iv
    gen_enc_key_iv(aes_key, aes_iv)
    return



def gen_enc_header(img_name):
    #=== step 3:pack the ecrypt image
    print("step 3: pack the encryption image")
    enc_img_header_file = os.path.join(TEMP_ENCRY_IMAGE_PATH,\
        'trustedcore_enc_header.bin')
    enc_img_final_file = img_name
    no_encry_img = img_name + '.no_encrypt'

    shutil.copyfile(enc_img_final_file, no_encry_img)
    os.remove(enc_img_final_file)
    shutil.copyfile(enc_img_header_file, enc_img_final_file)

    #add encry img total size
    enc_img_file = os.path.join(os.getcwd() + '/tmp_enc/trustedcore_enc.img')
    img_size = os.path.getsize(enc_img_file)
    print("The size of image file is {0}".format(img_size))
    header_info = struct.pack('<1I',
                    img_size)
    enc_img_fp = os.open(enc_img_final_file, os.O_RDWR | os.O_APPEND, 0o644)
    os.write(enc_img_fp, header_info)
    os.close(enc_img_fp)

    #enc img header total 548 bytes
    header_size = os.path.getsize(enc_img_final_file)
    mod = header_size % 548
    if mod:
        header_size += 548 - mod
    img = os.open(enc_img_final_file, os.O_RDWR | os.O_CREAT, 0o644)
    os.lseek(img, 0, 2)
    os.ftruncate(img, header_size)
    os.close(img)

    #add the encryt image append the header
    enc_img_fp = os.open(enc_img_final_file, os.O_RDWR | os.O_CREAT, 0o644)
    os.lseek(enc_img_fp, 0, 2)
    with open(enc_img_file, 'rb') as iv_fp:
        os.write(enc_img_fp, iv_fp.read())
    os.close(enc_img_fp)

    #remove the temp dir
    if os.path.exists(TEMP_ENCRY_IMAGE_PATH):
        shutil.rmtree(TEMP_ENCRY_IMAGE_PATH)
    print("End: succeed to pack the encryption image")
    #=== end
    return


def encryt_image(img_name):
    gen_enc_image(img_name)
    gen_enc_header(img_name)

if __name__ == '__main__':
    align_image(IMAGE_FILE)
    encryt_image(IMAGE_FILE)
