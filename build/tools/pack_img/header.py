#!/usr/bin/env python3
#trustedcore package header generator
# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
"""Description:package image for phone
"""
from __future__ import print_function
import struct
import os
import sys
import binascii
import shutil
import subprocess

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

compare_image = 0

img_paths = 0
task_names = 1
heap_sizes = 3
task_uuids = 2

elf_class = 0
tee_dict = {'TEE_GOT_START': 0,
'TEE_GOT_END': 0,
'TEE_RELPLT_START': 0,
'TEE_RELPLT_END': 0,
'TEE_RELDYN_START': 0,
'TEE_RELDYN_END': 0,
'TEE_RELADYN_START': 0,
'TEE_RELADYN_END': 0,
'TEE_DYNAMIC_START': 0,
'TEE_DYNAMIC_END': 0,
'TEE_DYNSYM_START': 0,
'TEE_DYNSYM_END': 0,
'TEE_RELAPLT_START': 0,
'TEE_RELAPLT_END': 0,
'GT_DATA_START': 0,
'GT_DATA_END': 0
}

EI_NIDENT = 16
ELFINFO_CLASS_64 = '\x02'
ELFINFO_MAG0 = '\x7f'
ELFINFO_MAG3 = 'F'
ELFINFO_MAG2_INDEX = 2
ELFINFO_MAG0_INDEX = 0
ELFINFO_CLASS_32 = '\x01'
ELFINFO_MAG1 = 'E'
ELFINFO_MAG1_INDEX = 1
ELFINFO_CLASS_INDEX = 4
ELFINFO_MAG2 = 'L'
ELFINFO_MAG3_INDEX = 3


def pack_header_item(input_file, img_addr, img_size, img_file):
    """package header item for image header"""
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


def get_file_size(name):
    """get file size for params"""
    size = os.path.getsize(name)
    mod = size % 4
    if mod:
        size += 4 - mod
    return size


#filelist:
#0: rtosck.img
#1: globaltask.img
#2-N: ta.sec
#N+1: encRndFile
def generate_header(files_list, header_filename):
    """generate image header"""
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
        for index in enumerate(t_filelist):
            img_offset_list.append(img_offset)
            img_size = filesize_list[index + 1]
            img_offset += img_size

        task_offset = header_size
        kernel_offset = header_size + filesize_total;
        print("kernel_size=0x{0:x}, load addr=0x{1:x}".format(
              kernel_size, kernel_load_addr))
        output_strs = struct.pack('<9I',
                                  header_size,
                                  kernel_load_addr,
                                  kernel_size,
                                  task_num,
                                  filesize_total,
                                  kernel_got_size,
                                  image_load_addr,
                                  task_offset,
                                  kernel_offset)
        file_names.write(output_strs)

        for index, imgfile in enumerate(t_filelist):
            img_offset = img_offset_list[index]
            img_size = filesize_list[index + 1]
            print("[{0}]:Name={1} addr=0x{2:x} size=0x{3:x}".format(index,
                  imgfile[task_names], img_offset, img_size))
            pack_header_item(file_names, img_offset, img_size, imgfile)

        output_strs = struct.pack('<4I',
                                  global_img_symtab_offset,
                                  global_img_symtab_size,
                                  global_img_strtab_size,
                                  global_img_bss_size)
        file_names.write(output_strs)

        output_strs = struct.pack('<4I',
                                  rtosck_img_symtab_offset,
                                  rtosck_img_symtab_size,
                                  rtosck_img_strtab_size,
                                  rtosck_img_bss_size)
        file_names.write(output_strs)

        global tee_dict
        global elf_class
        got_start = tee_dict.get('TEE_GOT_START')
        got_size = tee_dict.get('TEE_GOT_END') - tee_dict.get('TEE_GOT_START')
        relplt_start = tee_dict.get('TEE_RELPLT_START')
        relplt_size = tee_dict.get('TEE_RELPLT_END') - \
                      tee_dict.get('TEE_RELPLT_START')
        reldyn_start = tee_dict.get('TEE_RELDYN_START')
        reldyn_size = tee_dict.get('TEE_RELDYN_END') - \
                      tee_dict.get('TEE_RELDYN_START')
        reladyn_start = tee_dict.get('TEE_RELADYN_START')
        reladyn_size = tee_dict.get('TEE_RELADYN_END') - \
                       tee_dict.get('TEE_RELADYN_START')
        dynamic_start = tee_dict.get('TEE_DYNAMIC_START')
        dynamic_size = tee_dict.get('TEE_DYNAMIC_END') - \
                       tee_dict.get('TEE_DYNAMIC_START')
        dynsym_start = tee_dict.get('TEE_DYNSYM_START')
        dynsym_size = tee_dict.get('TEE_DYNSYM_END') - \
                      tee_dict.get('TEE_DYNSYM_START')
        relaplt_start = tee_dict.get('TEE_RELAPLT_START')
        relaplt_size = tee_dict.get('TEE_RELAPLT_END') - \
                       tee_dict.get('TEE_RELAPLT_START')
        gtdata_start = tee_dict.get('GT_DATA_START')
        gtdata_size = tee_dict.get('GT_DATA_END') - \
                      tee_dict.get('GT_DATA_START')

        elf_put = struct.pack('<17I',
                              elf_class,
                              got_start,
                              got_size,
                              relplt_start,
                              relplt_size,
                              reldyn_start,
                              reldyn_size,
                              reladyn_start,
                              reladyn_size,
                              dynamic_start,
                              dynamic_size,
                              dynsym_start,
                              dynsym_size,
                              relaplt_start,
                              relaplt_size,
                              gtdata_start,
                              gtdata_size)
        file_names.write(elf_put)

        #write image
        for index, imgfile in enumerate(t_filelist):
            offset = img_offset_list[index]
            file_names.seek(offset)
            print("place img_[{0}] at 0x{1:x}, imgfile:{2}".format(
                  index, offset, imgfile[img_paths]))
            with open(imgfile[img_paths], 'rb') as inf:
                file_names.write(inf.read())

        file_names.seek(kernel_offset)
        with open(kernel_file[img_paths], 'rb') as inf:
            file_names.write(inf.read())


#align image file according 64 bytes
def align_image(img_name):
    """image size align for 64 bytes"""
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


def encryt_image(img_name):
    """encrypto image"""
    if len(sys.argv) > 8:
        kecc1pub_file = sys.argv[8]
    else:
        print("kecc1pub_file not exist:do not do encryption.")
        return
    if kecc1pub_file.startswith('kecc1pub_'):
        print("kecc1pub_file exist:go on do encryption.")
    else:
        print("kecc1pub_file not exist:do not do encryption.")
        return

    pwd = sys.path[0]
    path_one = pwd + '/../prebuild/tee-kernel-release/tools/img_encry_tool/'
    path_two = pwd + \
               '/../prebuild/tee-kernel-local-release/tools/img_encry_tool/'
    if os.path.exists(path_one):
        wraptool_path = path_one
    elif os.path.exists(path_two):
        wraptool_path = path_two
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

    with open(krnd_file, 'rb') as rndfp:
        random = rndfp.read(rnd_file_size)
    rndfp.close()
    random_str = struct.unpack("32s", random)

    input_key_str = ''
    for rand_chr in random_str:
        input_key_str = input_key_str + rand_chr.decode("utf8", "ignore")
    aes_key = binascii.b2a_hex(input_key_str.encode())

    krnd_iv_file = tmp_encimg_file_path + 'krndIV.iv'
    subprocess.run(["openssl", "rand", "-out", \
              krnd_iv_file, "16"], shell=False, check=True)
    iv_file_size = os.path.getsize(krnd_iv_file)
    with open(krnd_iv_file, 'rb') as ivfps:
        iv_fps = ivfps.read(iv_file_size)
    ivfps.close()
    iv_str = struct.unpack("16s", iv_fps)

    input_key_str = ''
    for iv_chr in iv_str:
        input_key_str = input_key_str + iv_chr.decode("utf8", "ignore")
    aes_rnd_iv = binascii.b2a_hex(input_key_str.encode())

    #generate enc image
    enc_img_file = tmp_encimg_file_path + 'trustedcore_enc.img'
    subprocess.run(["openssl", "enc", "-aes-256-cbc", "-in", img_name, \
              "-out", enc_img_file, "-K", aes_key, "-iv", aes_rnd_iv], \
              shell=False, check=True)
    #encry img must be 64 bytes align
    align_image(enc_img_file)

    print("step 2: generate En_Krnd/IV")
    with open(krnd_file, 'ab') as rndfp:
        with open(krnd_iv_file, 'rb') as ivfps:
            rndfp.write(ivfps.read())
    rndfp.close()
    # use wrap tool to generate enc_img header:trustedcore_enc_header.bin
    wraptool_file = wraptool_path + 'wraptool.c'
    wraptool_outfile = wraptool_path + 'wraptool'
    fastboot_pubkey_file = wraptool_path + kecc1pub_file
    enc_img_head_file = tmp_encimg_file_path + 'trustedcore_enc_header.bin'

    subprocess.run(["cd", wraptool_path], shell=False, check=True)
    resp = subprocess.run([wraptool_outfile, krnd_file, fastboot_pubkey_file, \
              enc_img_head_file], shell=False, check=True)
    if resp.returncode == 0:
        print("suceed to do key wrap")
    else:
        raise RuntimeError("Failed to do key wrap process.")
    subprocess.run(["cd", "-"], shell=False, check=True)

    subprocess.run(["cp", img_name, tmp_encimg_file_path, \
              "/"], shell=False, check=True)

    #=== step 3:pack the ecrypt image
    #then add the len and  trustedcore_enc.img
    print("step 3: pack the encryption image")
    enc_img_final_file = img_name
    no_encry_img = img_name + '.no_encrypt'
    subprocess.run(["cp", enc_img_final_file, no_encry_img], \
              shell=False, check=True)
    subprocess.run(["rm", enc_img_final_file], shell=False, check=True)
    resp = subprocess.run(["cp", enc_img_head_file, enc_img_final_file], \
            shell=False, check=True)
    if resp == 0:
        print("suceed to cp trustedcore_enc_header.bin")
    else:
        raise RuntimeError("Failed to cp trustedcore_enc_header.bin.")

    #add encry img total size
    img_size = os.path.getsize(enc_img_file)
    print("The size of image file is {0}".format(img_size))
    write_text = struct.pack('<1I',
                    img_size)
    with open(enc_img_final_file, 'ab') as enc_img_fp:
        enc_img_fp.write(write_text)
    enc_img_fp.close()

    #enc img header total 256 bytes
    img_head_size = os.path.getsize(enc_img_final_file)
    mod = img_head_size % 256
    if mod:
        img_head_size += 256 - mod
    with open(enc_img_final_file, 'ab+') as img:
        img.seek(0, 2)
        img.truncate(img_head_size)
    img.close()

    #add the encryt image append the header
    with open(enc_img_final_file, 'ab') as enc_img_fp:
        with open(enc_img_file, 'rb') as ivfps:
            enc_img_fp.write(ivfps.read())
    enc_img_fp.close()

    #remove the temp dir
    if os.path.exists(tmp_encimg_file_path):
        shutil.rmtree(tmp_encimg_file_path)
    print("End: succeed to pack the encryption image")
    #=== end


if __name__ == '__main__':

    input_file_list = []
    internal_task_list = []
    image_file_path = sys.argv[1]
    input_kernel_file = sys.argv[2],
    kernel_load_addr = int(sys.argv[3], 16)
    kernel_got_size = int(sys.argv[4], 16)
    input_file_list.append(input_kernel_file)

    rtosck_sym_head_args = sys.argv[5]
    rtosck_sym_item = rtosck_sym_head_args.split(',');
    rtosck_img_symtab_offset = int(rtosck_sym_item[0])
    rtosck_img_symtab_size = int(rtosck_sym_item[1], 16)
    rtosck_img_strtab_size = int(rtosck_sym_item[2]) - rtosck_img_symtab_size;

    compare_image = int(sys.argv[6], 10)

    image_load_addr = int(sys.argv[7], 16)

    pwd_path = sys.path[0]
    tmp_internal_task_path = pwd_path + '/tmp/'
    print("cwd={0}, tmp_internal_task_path={1}".format(
          pwd_path, tmp_internal_task_path))
    if os.path.exists(tmp_internal_task_path):
        shutil.rmtree(tmp_internal_task_path)
    os.mkdir(tmp_internal_task_path)

    #encrypt verify elf
    for index_elf, taskitem in enumerate(input_file_list):
        if index_elf in (0, 1):
            internal_task_list.append(taskitem)
        continue

    generate_header(internal_task_list, image_file_path)
    shutil.rmtree(tmp_internal_task_path)
    align_image(image_file_path)
    encryt_image(image_file_path)
