#!/usr/bin/env python3
#trustedcore package header generator for kunpeng
# Copyright Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.

from __future__ import print_function
import struct
import os
import sys
import binascii
import shutil
import subprocess
from pack_key import add_pub_key_to_header
from pack_key import add_cert_pub_to_header
from pack_key import add_ta_loadkey_to_header
from pack_key import align_header

header_size = 0x400
kernel_load_addr = 0
image_load_addr = 0
global_img_symtab_offset = 0
global_img_symtab_size = 0
global_img_strtab_size = 0
global_img_bss_size = 0
rtosck_img_symtab_offset = 0
rtosck_img_symtab_size = 0
rtosck_img_strtab_size = 0
rtosck_img_bss_size = 0
sig_key_version = 0

compare_image = 0

img_paths = 0
task_names = 1
heap_sizes = 3
task_uuids = 2

ca_rsa_header_offset = 64
ta_rsa_header_offset = ca_rsa_header_offset + 12
ta_root_cert_offset = ta_rsa_header_offset + 12
ta_config_cert_offset = ta_root_cert_offset + 12
ta_ecies_header_offset = ta_config_cert_offset + 12
ta_wb_header_offset = ta_ecies_header_offset + 12
ca_rsa_magic = 0x5a5aa501
ta_rsa_magic = 0x5a5aa502
ta_cert_magic = 0x5a5aa503
ta_config_magic = 0x5a5aa504
ta_ecies_magic = 0x5a5aa505
ta_wb_magic = 0x5a5aa506
ca_path = "ca_public_key.pem"
ta_path = "pubkey/phone_public_key.cer"
ta_root_cert_path = "pubkey/huawei_it_product_kunpeng.cer"
ta_config_cert_path = "pubkey/public_config_key_kunpeng.der"
ecies_path = "pubkey/ecies_kunpeng.der"
wb_path = "pubkey/wbkey_kunpeng.der"

def pack_header_item(input_file, img_addr, img_size, img_file):
    task_size = img_file[heap_sizes]
    task_name = img_file[task_names]
    task_uuid = img_file[task_uuids]
    out_strs = struct.pack('<3I20s16s',
                           img_addr,
                           img_size,
                           task_size,
                           task_name.encode("utf-8"),
                           task_uuid.encode("utf-8"));
    input_file.write(out_strs)

def update_header_after_sign(tee_path):
    header = 0
    file = open(tee_path, "rb+")
    print("file name:", file.name)
    file.seek(0, 0)
    header_str = file.read(64)
    header = struct.unpack('<IQ4I3QIQ', header_str)
    print(header)

    header_size = header[0]
    kernel_offset = header[8]
    sig_offset = header[10] + header_size - kernel_offset
    kernel_offset = header_size

    print(sig_offset)
    print(kernel_offset)
    out_strs = struct.pack('<IQ4I3QIQ',
            header[0],
            header[1],
            header[2],
            header[3],
            header[4],
            header[5],
            header[6],
            header[7],
            kernel_offset,
            header[9],
            sig_offset)
    file.seek(0,0)
    img_str = file.read();
    new_str = out_strs + img_str[64:]
    file.seek(0,0)
    file.write(new_str)
    return

def get_file_size(name):

    size = os.path.getsize(name)
    mod = size % 4
    if mod:
        size += 4 - mod

    return size


def append_signature():

    signature_file = "./output/stage/trustedcore.img"
    subprocess.run(["sign_cloud", signature_file], shell=False)
    sign_file = signature_file + ".rsa"
    cmake_signature_file = "../../../../hm-teeos/images/trustedcore.img"
    subprocess.run(["sign_cloud", cmake_signature_file], \
            shell=False)
    cmake_sign_file = cmake_signature_file + ".rsa"
    if not os.path.exists(sign_file):
        if not os.path.exists(cmake_sign_file):
            print("the file {0} not exist".format(cmake_sign_file))
            return 1
        with open(cmake_signature_file, 'ab+') as signature_fp:
            with open(cmake_sign_file, 'rb') as sign_fp:
                sign_data = sign_fp.read()
            sign_fp.close()
            signature_fp.write(sign_data)
        signature_fp.close()
        subprocess.run(["rm", cmake_sign_file], shell=False, check=True)
    else:
        with open(signature_file, 'ab+') as signature_fp:
            with open(sign_file, 'rb') as sign_fp:
                sign_data = sign_fp.read()
            sign_fp.close()
            signature_fp.write(sign_data)
        signature_fp.close()
        subprocess.run(["rm", sign_file], shell=False, check=True)
    return 0


#filelist:
#0: rtosck.img
#1: globaltask.img
#2-N: ta.sec
#N+1: encRndFile
def generate_header(files_list, header_filename):

    with open(header_filename, 'wb') as file_names:

        t_filelist = files_list[1:]
        task_num = len(t_filelist)
        filesize_list = [get_file_size(i[img_paths]) for i in files_list]
        img_offset_list = []
        kernel_file = files_list[0]
        kernel_size = filesize_list[0]

        filesize_total = sum(filesize_list[1:])

        offset = header_size
        img_offset = offset
        for index, imgfile in enumerate(t_filelist):
            img_offset_list.append(img_offset)
            img_size = filesize_list[index + 1]
            img_offset += img_size

        task_offset = header_size
        kernel_offset = header_size + filesize_total;
        sig_offset = kernel_offset + os.path.getsize(kernel_file[0])
        mod = sig_offset % 64
        sig_offset += 64 - mod
        print("kernel_size=={0}, load addr==0x{1:x}".format(
              kernel_size, kernel_load_addr))
        out_strs = struct.pack('<IQ4I3QIQ',
                                header_size,
                                kernel_load_addr,
                                kernel_size,
                                task_num,
                                filesize_total,
                                kernel_got_size,
                                image_load_addr,
                                task_offset,
                                kernel_offset,
                                sig_key_version,
                                sig_offset)
        file_names.write(out_strs)

        file_names.seek(kernel_offset)
        with open(kernel_file[img_paths], 'rb') as inf:
            file_names.write(inf.read())


#align image file according 64 bytes
def align_image(img_name):

    img_size = os.path.getsize(img_name)
    print("The size of image file is {0}".format(img_size))

    mod = img_size % 64
    if mod:
        img_size += 64 - mod

    with open(img_name, 'ab+') as img:
        img.seek(0, 2)
        img.truncate(img_size)

    img.close()
    img_size = os.path.getsize(img_name)
    print("After align, the size of image file is {0}".format(img_size))


def bytes_to_hexstr(bs):

    return ''.join(['%02x' % b for b in bs])


def encryt_image(img_name):

    if len(sys.argv) > 8:
        krsapub_file = sys.argv[8]
    else:
        print("krsapub_file not exist:do not do encryption.")
        return
    if krsapub_file.startswith('krsa'):
        print("krsapub_file exist:go on do encryption.")
    else:
        print("krsapub_file not exist:do not do encryption.")
        return

    pwd = sys.path[0]
    wraptool_path_a = pwd + \
                     '/../prebuild/hm-teeos-release/tools/img_encry_tool/'
    wraptool_path_b = pwd + \
                    '/../prebuild/hm-teeos-local-release/tools/img_encry_tool/'
    if os.path.exists(wraptool_path_a):
        wraptool_path = wraptool_path_a
    elif os.path.exists(wraptool_path_b):
        wraptool_path = wraptool_path_b
    else:
        print("img_encry_tool path not exists")
        return
    #=== create temp dir for image encryption
    tmp_encimg_file_path = wraptool_path + 'tmp_enc/'
    if os.path.exists(tmp_encimg_file_path):
        shutil.rmtree(tmp_encimg_file_path)
    os.mkdir(tmp_encimg_file_path)

    #=== step 1: generate Krnd/IV, used to encrypimage
    print("step 1: generate Krnd/IV")
    krnd_file = tmp_encimg_file_path + 'krnd.rnd'
    subprocess.run(["openssl", "rand", "-out", krnd_file, \
              "32"], shell=False, check=True)
    rnd_file_size = os.path.getsize(krnd_file)

    with open(krnd_file, 'rb') as rnd_fp:
        random = rnd_fp.read(rnd_file_size)
    rnd_fp.close()
    random_str = struct.unpack("32s", random)

    input_key_str = ''
    aes_key = ''
    for rand_chr in random_str:
        input_key_str = bytes_to_hexstr(rand_chr)
        aes_key = aes_key + input_key_str

    #generate krndIV
    krnd_iv_file = tmp_encimg_file_path + 'krndIV.iv'
    subprocess.run(["openssl", "rand", "-out", \
              krnd_iv_file, "16"], shell=False, check=True)
    iv_file_size = os.path.getsize(krnd_iv_file)
    with open(krnd_iv_file, 'rb') as ivfps:
        iv_fps = ivfps.read(iv_file_size)
    ivfps.close()
    iv_str = struct.unpack("16s", iv_fps)

    input_key_str = ''
    aes_rnd_iv = ''
    for iv_chr in iv_str:
        input_key_str = bytes_to_hexstr(iv_chr)
        aes_rnd_iv = aes_rnd_iv + input_key_str
    img_encry_makefile = "{}{}".format(pwd, "/img_encry_kunpeng/Makefile")
    subprocess.run(["make", "-j", "-f", \
              img_encry_makefile], shell=False, check=True)

    #generate enc image
    enc_img_file = tmp_encimg_file_path + 'trustedcore_enc.img'
    enc_tool_file = pwd + "/img_encry_kunpeng/img_encry"
    tagfile = tmp_encimg_file_path + 'tag.bin'
    subprocess.run([enc_tool_file, "-in", img_name, "-out", \
              enc_img_file, "-K", aes_key, "-iv", aes_rnd_iv, \
              "-tag", tagfile], shell=False, check=True)
    #encry img must be 64 bytes align,
    #else img verification will failed when fastboot load
    subprocess.run(["make", "-j", "-f", img_encry_makefile, \
              "clean"], shell=False, check=True)
    align_image(enc_img_file)

    #=== step 2:generate En_Krnd/IV
    print("step 2: generate En_Krnd/IV")
    # pack Krnd and KrndIV to one file
    krnd_all_file = tmp_encimg_file_path + 'krnd.all'

    with open(krnd_all_file, 'ab') as rnd_fp:
        with open(krnd_file, 'rb') as ivfp:
            rnd_fp.write(ivfp.read())
        with open(krnd_iv_file, 'rb') as ivfp:
            rnd_fp.write(ivfp.read())
        with open(tagfile, 'rb') as ivfp:
            rnd_fp.write(ivfp.read())
    rnd_fp.close()
    #use rsa pubkey to encrypt Krnd/IV
    fastboot_pubkey_file = wraptool_path + krsapub_file
    enc_rnd_file = krnd_all_file + '.sec'
    subprocess.run(["openssl", "rsautl", "-encrypt", "-pubin", "-oaep", \
              "-inkey", fastboot_pubkey_file, "-in", krnd_all_file, \
              "-out", enc_rnd_file], shell=False, check=True)
    #add En_Krnd/IV to trustedcore_enc_header.bin
    encimg_header_file = tmp_encimg_file_path + 'trustedcore_enc_header.bin'

    encrnd_file_size = os.path.getsize(enc_rnd_file)
    with open(enc_rnd_file, 'rb') as enc_rnd_fp:
        enc_rnd_str = enc_rnd_fp.read(encrnd_file_size)
    enc_rnd_fp.close()

    img_magic_num = 0x5A5AA5A5
    img_format_version = 0x10100
    img_reverse = [0, 0, 0, 0, 0, 0]
    out_enc_head = struct.pack('<8I512s',
                    img_magic_num,
                    img_format_version,
                    img_reverse[0],
                    img_reverse[1],
                    img_reverse[2],
                    img_reverse[3],
                    img_reverse[4],
                    img_reverse[5],
                    enc_rnd_str);

    with open(encimg_header_file, 'ab') as encimg_head_fp:
        encimg_head_fp.write(out_enc_head)
    encimg_head_fp.close()

    #=== step 3:pack the ecrypt image
    #cp trustedcore_enc_header.bin to out/xxx/trustedcore.img
    #then add the len and  trustedcore_enc.img
    print("step 3: pack the encryption image")
    encimg_final_file = img_name
    no_encry_img = img_name + '.no_encrypt'
    subprocess.run(["cp", encimg_final_file, no_encry_img], \
              shell=False, check=True)
    subprocess.run(["rm", encimg_final_file], shell=False, check=True)
    resp = subprocess.run(["cp", encimg_header_file, encimg_final_file], \
              shell=False, check=True)
    if resp.returncode == 0:
        print("suceed to cp trustedcore_enc_header.bin")
    else:
        raise RuntimeError("Failed to cp trustedcore_enc_header.bin.")

    #add encry img total size
    img_size = os.path.getsize(enc_img_file)
    print("The size of image file is {0}".format(img_size))
    out_img_str = struct.pack('<1I', img_size)

    with open(encimg_final_file, 'ab') as encimg_fp:
        encimg_fp.write(out_img_str)
    encimg_fp.close()

    #enc img header total 548 bytes
    header_size = os.path.getsize(encimg_final_file)
    mod = header_size % 548
    if mod:
        header_size += 548 - mod
    with open(encimg_final_file, 'ab+') as img:
        img.seek(0, 2)
        img.truncate(header_size)
    img.close()

    #add the encryt image append the header
    with open(encimg_final_file, 'ab') as encimg_fp:
        with open(enc_img_file, 'rb') as ivfp:
            encimg_fp.write(ivfp.read())
    encimg_fp.close()

    #remove the temp dir
    if os.path.exists(tmp_encimg_file_path):
        shutil.rmtree(tmp_encimg_file_path)
    print("End: succeed to pack the encryption image")


def noencryt_image(src_name):

    pwd_path = sys.path[0]

    encimgfinalfile = src_name
    no_encry_img = src_name + '.no_encrypt'
    subprocess.run(["cp", encimgfinalfile, " ", no_encry_img], \
              shell=False, check=True)
    subprocess.run(["rm", encimgfinalfile], shell=False, check=True)

    img_magic_num = 0x5A5AA5A5
    img_format_version = 0x1010100
    img_reverse = [0, 0, 0, 0, 0, 0]
    encrndstr = "dead"
    z = struct.pack('<8I512s',
                    img_magic_num,
                    img_format_version,
                    img_reverse[0],
                    img_reverse[1],
                    img_reverse[2],
                    img_reverse[3],
                    img_reverse[4],
                    img_reverse[5],
                    bytes(encrndstr.encode('utf-8')));

    dst_file = pwd_path + "/../output/stage/trustedcore.img"
    with open(dst_file, 'ab') as encimgheadfp:
        encimgheadfp.write(z)
    encimgheadfp.close()

    print("step 1: pack the encryption image")

    #add encry img total size
    img_size = os.path.getsize(no_encry_img)
    print("The size of image file is {0}".format(img_size))
    z = struct.pack('<1I',
                    img_size)

    with open(dst_file, 'ab') as encimgfp:
        encimgfp.write(z)
    encimgfp.close()

    #enc img header total 548 bytes
    header_size = os.path.getsize(dst_file)
    mod = header_size % 548
    if mod:
        header_size += 548 - mod
    with open(dst_file, 'ab+') as img:
        img.seek(0, 2)
        img.truncate(header_size)
    img.close()

    #add the encryt image append the header
    with open(dst_file, 'ab') as encimgfp:
        with open(no_encry_img, 'rb') as ivfp:
            encimgfp.write(ivfp.read())
    encimgfp.close()

    print("End: succeed to pack the noencryption image")

if __name__ == '__main__':

    input_file_list = []
    internal_task_list = []
    image_file_path = sys.argv[1]
    input_kernel_file = sys.argv[2],
    kernel_load_addr = int(sys.argv[3], 16)
    kernel_got_size = int(sys.argv[4], 16)
    input_file_list.append(input_kernel_file)


    compare_image = int(sys.argv[6], 10)
    image_load_addr = int(sys.argv[7], 16)

    #encrypt verify elf
    for list_index, taskitem in enumerate(input_file_list):
        if list_index == 0 or list_index == 1:
            internal_task_list.append(taskitem)
            continue

    generate_header(internal_task_list, image_file_path)
    align_image(image_file_path)
    print("before sign {0}".format(os.path.getsize(image_file_path)))

    #add ta pub
    print(image_file_path)
    pwd = sys.path[0] + '/'
    print(pwd)
    add_cert_pub_to_header(image_file_path, pwd + ta_root_cert_path, ta_root_cert_offset, ta_cert_magic)
    add_pub_key_to_header(image_file_path, pwd + ta_config_cert_path, ta_config_cert_offset, ta_config_magic)
    #add ecise or wbkey
    if len(sys.argv) > 8:
        add_ta_loadkey_to_header(image_file_path, pwd + ecies_path, ta_ecies_header_offset, ta_ecies_magic)
    else:
        add_ta_loadkey_to_header(image_file_path, pwd + wb_path, ta_wb_header_offset, ta_wb_magic)

    align_header(image_file_path)

    update_header_after_sign(image_file_path)
    ret = append_signature()
    if ret == 1:
        print("append signature failed")
        sys.exit(ret)
    print("after sign {0}".format(os.path.getsize(image_file_path)))

    if len(sys.argv) > 8:
        encryt_image(image_file_path)
    else:
        noencryt_image(image_file_path)

