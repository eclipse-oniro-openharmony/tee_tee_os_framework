#!/usr/bin/env python3
# trustedcore package header generator
# Copyright (c) Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

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

CompareImage = 0

ImgPath = 0
Taskname = 1
Heapsize = 3
Taskuuid = 2

# set globaltask relocation info to image header
elf_class = 0
dic = {'TEE_GOT_START': 0,
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
ELFINFO_MAG0_INDEX        = 0
ELFINFO_MAG1_INDEX        = 1
ELFINFO_MAG2_INDEX        = 2
ELFINFO_MAG3_INDEX        = 3
ELFINFO_MAG0              = '\x7f'
ELFINFO_MAG1              = 'E'
ELFINFO_MAG2              = 'L'
ELFINFO_MAG3              = 'F'
ELFINFO_CLASS_INDEX       = 4
ELFINFO_CLASS_32          = '\x01'
ELFINFO_CLASS_64          = '\x02'


def pack_header_item(f, img_addr, img_size, img_file):
    task_size = img_file[Heapsize]
    task_name = img_file[Taskname]
    task_uuid = img_file[Taskuuid]
    z = struct.pack('<3I20s16s',
                    img_addr,
                    img_size,
                    task_size,
                    task_name.encode("utf-8"),
                    task_uuid.encode("utf-8"));
    f.write(z)


def getfilesize(name):
    size = os.path.getsize(name)
    #align 4
    mod = size % 4
    if mod:
        size += 4 - mod
    return size


#file_list:
#0: rtosck.img
#1: globaltask.img
#2-N: ta.sec
#N+1: encRndFile
def generate_header(file_list, header_filename):
    with open(header_filename, 'wb') as f:
        t_filelist = file_list[1:]
        task_num = len(t_filelist)
        filesize_list = [getfilesize(i[ImgPath]) for i in file_list]
        img_offset_list = []
        kernelfile = file_list[0]
        kernel_size = filesize_list[0]
        filesize_total = sum(filesize_list[1:])

        offset = header_size
        img_offset = offset
        for index, imgfile in enumerate(t_filelist):
            img_offset_list.append(img_offset)
            img_size = filesize_list[index + 1]
            img_offset += img_size

        task_offset = header_size
        kernel_offset = header_size + filesize_total
        temp_header_size = kernel_offset
        z = struct.pack('<9I',
                        temp_header_size,
                        kernel_load_addr,
                        kernel_size,
                        task_num,
                        filesize_total,
                        kernel_got_size,
                        image_load_addr,
                        task_offset,
                        kernel_offset)
        f.write(z)

        for index, imgfile in enumerate(t_filelist):
            img_offset = img_offset_list[index]
            img_size = filesize_list[index + 1]
            print("[{0}]: taskName={1}, img_addr=0x{2:x}, img_size=0x{3:x}".
                    format(index, imgfile[Taskname], img_offset, img_size))
            pack_header_item(f, img_offset, img_size, imgfile)

        z = struct.pack('<4I',
                        global_img_symtab_offset,
                        global_img_symtab_size,
                        global_img_strtab_size,
                        global_img_bss_size)
        f.write(z)

        z = struct.pack('<4I',
                        rtosck_img_symtab_offset,
                        rtosck_img_symtab_size,
                        rtosck_img_strtab_size,
                        rtosck_img_bss_size)
        f.write(z)

        # set globaltask relocation info to image header
        global dic
        global elf_class
        got_start = dic['TEE_GOT_START']
        got_size = dic['TEE_GOT_END'] - dic['TEE_GOT_START']
        relplt_start = dic['TEE_RELPLT_START']
        relplt_size = dic['TEE_RELPLT_END'] - dic['TEE_RELPLT_START']
        reldyn_start = dic['TEE_RELDYN_START']
        reldyn_size = dic['TEE_RELDYN_END'] - dic['TEE_RELDYN_START']
        reladyn_start = dic['TEE_RELADYN_START']
        reladyn_size = dic['TEE_RELADYN_END'] - dic['TEE_RELADYN_START']
        dynamic_start = dic['TEE_DYNAMIC_START']
        dynamic_size = dic['TEE_DYNAMIC_END'] - dic['TEE_DYNAMIC_START']
        dynsym_start = dic['TEE_DYNSYM_START']
        dynsym_size = dic['TEE_DYNSYM_END'] - dic['TEE_DYNSYM_START']
        relaplt_start = dic['TEE_RELAPLT_START']
        relaplt_size = dic['TEE_RELAPLT_END'] - dic['TEE_RELAPLT_START']
        gtdata_start = dic['GT_DATA_START']
        gtdata_size = dic['GT_DATA_END'] - dic['GT_DATA_START']

        # dump relocation info
        print("elf class: {0}".format(elf_class))
        print("got start: 0x{0:x} end: 0x{1:x}".format(
                dic['TEE_GOT_START'], dic['TEE_GOT_END']))
        print("relplt start: 0x{0:x} end: 0x{1:x}".format(
                dic['TEE_RELPLT_START'], dic['TEE_RELPLT_END']))
        print("reldyn start: 0x{0:x} end: 0x{1:x}".format(
                dic['TEE_RELDYN_START'], dic['TEE_RELDYN_END']))
        print("reladyn start: 0x{0:x} end: 0x{1:x}".format(
                dic['TEE_RELADYN_START'], dic['TEE_RELADYN_END']))
        print("dynsym start: 0x{0:x} end: 0x{1:x}".format(
                dic['TEE_DYNSYM_START'], dic['TEE_DYNSYM_END']))
        print("relaplt start: 0x{0:x} end: 0x{1:x}".format(
                dic['TEE_RELAPLT_START'], dic['TEE_RELAPLT_END']))
        print("gtdata start: 0x{0:x} end: 0x{1:x}".format(
                dic['GT_DATA_START'], dic['GT_DATA_END']))
        print("got size: {0}".format(got_size))
        print("relplt size: {0}".format(relplt_size))
        print("reldyn size: {0}".format(reldyn_size))
        print("reladyn size: {0}".format(reladyn_size))
        print("dynamic size: {0}".format(dynamic_size))
        print("dynsym size: {0}".format(dynsym_size))
        print("relaplt size: {0}".format(relaplt_size))
        print("relaplt size: {0}".format(gtdata_size))

        el = struct.pack('<17I',
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
        f.write(el)

        # write image
        for index, imgfile in enumerate(t_filelist):
            offset = img_offset_list[index]
            f.seek(offset)
            print("place img_[{0}] at 0x{1:x}, imgfile:{2}".format(
                    index, offset, imgfile[ImgPath]))
            with open(imgfile[ImgPath], 'rb') as inf:
                f.write(inf.read())

        f.seek(kernel_offset)
        with open(kernelfile[ImgPath], 'rb') as inf:
            f.write(inf.read())


# align image file according 64 bytes
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


def encryt_image(img_name):
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

    current_path = sys.path[0]
    tool_path_a = '/../prebuild/hm-teeos-release/tools/img_encry_tool/'
    tool_path_b = '/../prebuild/hm-teeos-local-release/tools/img_encry_tool/'
    wraptool_path_a = current_path + tool_path_a
    wraptool_path_b = current_path + tool_path_b
    if os.path.exists(wraptool_path_a):
        wraptool_path = wraptool_path_a
    elif os.path.exists(wraptool_path_b):
        wraptool_path = wraptool_path_b
    else:
        print("img_encry_tool path not exists")
        return

    #=== create temp dir for image encryption
    tmp_enc_img_file_path = wraptool_path + 'tmp_enc/'
    if os.path.exists(tmp_enc_img_file_path):
        shutil.rmtree(tmp_enc_img_file_path)
    os.mkdir(tmp_enc_img_file_path)

    #=== step 1: generate Krnd/IV, used to encrypimage
    print("step 1: generate Krnd/IV")
    krnd_file = tmp_enc_img_file_path + 'krnd.rnd'
    subprocess.run(["openssl", "rand", "-out", krnd_file, \
               "32"], shell=False, check=True)
    rnd_file_size = os.path.getsize(krnd_file)

    with open(krnd_file, 'rb') as rnd_fp:
        random = rnd_fp.read(rnd_file_size)
    rnd_fp.close()
    random_str = struct.unpack("32s", random)

    input_key_str = ''
    for char in random_str:
        input_key_str = input_key_str + char.decode("utf8", "ignore")
    aes_key = binascii.b2a_hex(input_key_str.encode())

    #generate krndIV
    kind_id_file = tmp_enc_img_file_path + 'krndIV.iv'
    subprocess.run(["openssl", "rand", "-out", kind_id_file, \
               "16"], shell=False, check=True)
    iv_file_size = os.path.getsize(kind_id_file)
    with open(kind_id_file, 'rb') as iv_fp:
        iv = iv_fp.read(iv_file_size)
    iv_fp.close()
    iv_str = struct.unpack("16s", iv)

    input_key_str = ''
    for char in iv_str:
        input_key_str = input_key_str + char.decode("utf8", "ignore")
    aes_rnd_iv = binascii.b2a_hex(input_key_str.encode())

    #generate enc image
    enc_img_file = tmp_enc_img_file_path + 'trustedcore_enc.img'
    subprocess.run(["openssl", "enc", "-aes-256-cbc", "-in", img_name, \
               "-out", enc_img_file, "-K", aes_key, "-iv", aes_rnd_iv], \
               shell=False, check=True)

    #encry img must be 64 bytes align
    #else img verification will failed when fastboot load
    align_image(enc_img_file)

    #=== step 2:generate En_Krnd/IV
    # pack Krnd and KrndIV to one file
    print("step 2: generate En_Krnd/IV")
    with open(krnd_file, 'ab') as rnd_fp:
        with open(kind_id_file, 'rb') as iv_fp:
            rnd_fp.write(iv_fp.read())
    rnd_fp.close()

    # use wrap tool to generate enc_img header:trustedcore_enc_header.bin
    wraptool_file = wraptool_path + 'wraptool.c'
    wraptool_outfile = wraptool_path + 'wraptool'
    fastboot_pubkey_file = wraptool_path + kecc1pub_file
    enc_img_header_file = tmp_enc_img_file_path + 'trustedcore_enc_header.bin'
    subprocess.run(["cd", wraptool_path], shell=False, check=True)
    resp = subprocess.run([wraptool_outfile, krnd_file, fastboot_pubkey_file,
                   enc_img_header_file], shell=False, check=True)
    if resp == 0:
        print("suceed to do key wrap")
    else:
        raise RuntimeError("Failed to do key wrap process.")
    subprocess.run(["cd", "-"], shell=False, check=True)
    subprocess.run(["cp", img_name, tmp_enc_img_file_path], \
              shell=False, check=True)

    #=== step 3:pack the ecrypt image
    #cp trustedcore_enc_header.bin to out/xxx/trustedcore.img
    #then add the len and  trustedcore_enc.img
    print("step 3: pack the encryption image")
    enc_img_final_file = img_name
    no_encry_img = img_name + '.no_encrypt'
    subprocess.run(["cp", enc_img_final_file, no_encry_img], \
              shell=False, check=True)
    subprocess.run(["rm", enc_img_final_file], shell=False, check=True)
    resp = subprocess.run(["cp", enc_img_header_file, enc_img_final_file], \
              shell=False, check=True)
    if resp.returncode == 0:
        print("suceed to cp trustedcore_enc_header.bin")
    else:
        raise RuntimeError("Failed to cp trustedcore_enc_header.bin.")

    #add encry img total size
    img_size = os.path.getsize(enc_img_file)
    print("The size of image file is {0}".format(img_size))
    z = struct.pack('<1I', img_size)
    with open(enc_img_final_file, 'ab') as enc_img_fp:
        enc_img_fp.write(z)
    enc_img_fp.close()

    #enc img header total 256 bytes
    header_size = os.path.getsize(enc_img_final_file)
    mod = header_size % 256
    if mod:
        header_size += 256 - mod
    with open(enc_img_final_file, 'ab+') as img:
        img.seek(0, 2)
        img.truncate(header_size)
    img.close()

    #add the encryt image append the header
    with open(enc_img_final_file, 'ab') as enc_img_fp:
        with open(enc_img_file, 'rb') as iv_fp:
            enc_img_fp.write(iv_fp.read())
    enc_img_fp.close()

    #remove the temp dir
    if os.path.exists(tmp_enc_img_file_path):
        shutil.rmtree(tmp_enc_img_file_path)
    print("End: succeed to pack the encryption image")
    #=== end


if __name__ == '__main__':

    filelist = []
    internal_task_list = []
    dst_file = sys.argv[1]
    kernel_file = sys.argv[2],
    kernel_load_addr = int(sys.argv[3], 16)
    kernel_got_size = int(sys.argv[4], 16)
    filelist.append(kernel_file)

    rtosck_sym_head_args = sys.argv[5]
    rtosck_sym_item = rtosck_sym_head_args.split(',')
    rtosck_img_symtab_offset = int(rtosck_sym_item[0])
    rtosck_img_symtab_size = int(rtosck_sym_item[1], 16)
    rtosck_img_strtab_size = int(rtosck_sym_item[2]) - rtosck_img_symtab_size


    CompareImage = int(sys.argv[6], 10)

    image_load_addr = int(sys.argv[7], 16)

    pwd_path = sys.path[0]
    tmp_internal_task_path = pwd_path + '/tmp/'
    print("cwd={0}, tmp_internal_task_path={1}".format(
           pwd_path, tmp_internal_task_path))
    if os.path.exists(tmp_internal_task_path):
        shutil.rmtree(tmp_internal_task_path)
    os.mkdir(tmp_internal_task_path)

    #encrypt verify elf
    for index, taskitem in enumerate(filelist):
        if index == 0 or index == 1:
            internal_task_list.append(taskitem)
            continue

    generate_header(internal_task_list, dst_file)
    shutil.rmtree(tmp_internal_task_path)
    align_image(dst_file)
    encryt_image(dst_file)
