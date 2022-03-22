#!/usr/bin/env python3
#trustedcore package header generator
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

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

img_path = 0
task_name = 1
heap_size = 3
task_uuid = 2

elf_class = 0
dict = {'TEE_GOT_START': 0,
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


def packHeaderItem(f, img_addr, img_size, img_file):

    task_size = img_file[heap_size]
    task_name = img_file[task_name]
    task_uuid = img_file[task_uuid]
    z = struct.pack('<3I20s16s',
                    img_addr,
                    img_size,
                    task_size,
                    task_name,
                    task_uuid);
    f.write(z)


def getfilesize(name):

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
def generate_header(filelist, header_filename):

    with open(header_filename, 'wb') as f:
        t_filelist = filelist[1:]
        task_num = len(t_filelist)
        filesize_list = [getfilesize(i[img_path]) for i in filelist]
        img_offset_list = []
        kernel_file = filelist[0]
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
        print("kernel_size==0x{0:x}, load addr==0x{1:x}".format(
              kernel_size, kernel_load_addr))
        z = struct.pack('<9I',
                        header_size,
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
            print("[{0}]: task_name={1}, img_addr=0x{2:x}, \
                  img_size=0x{3:x}".format(
                  index, imgfile[task_name], img_offset, img_size))
            packHeaderItem(f, img_offset, img_size, imgfile)

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

        global dict
        global elf_class
        got_start = dict['TEE_GOT_START']
        got_size = dict['TEE_GOT_END'] - dict['TEE_GOT_START']
        relplt_start = dict['TEE_RELPLT_START']
        relplt_size = dict['TEE_RELPLT_END'] - dict['TEE_RELPLT_START']
        reldyn_start = dict['TEE_RELDYN_START']
        reldyn_size = dict['TEE_RELDYN_END'] - dict['TEE_RELDYN_START']
        reladyn_start = dict['TEE_RELADYN_START']
        reladyn_size = dict['TEE_RELADYN_END'] - dict['TEE_RELADYN_START']
        dynamic_start = dict['TEE_DYNAMIC_START']
        dynamic_size = dict['TEE_DYNAMIC_END'] - dict['TEE_DYNAMIC_START']
        dynsym_start = dict['TEE_DYNSYM_START']
        dynsym_size = dict['TEE_DYNSYM_END'] - dict['TEE_DYNSYM_START']
        relaplt_start = dict['TEE_RELAPLT_START']
        relaplt_size = dict['TEE_RELAPLT_END'] - dict['TEE_RELAPLT_START']
        gtdata_start = dict['GT_DATA_START']
        gtdata_size = dict['GT_DATA_END'] - dict['GT_DATA_START']

        print("elf class: {0}".format(elf_class))
        print("got start: 0x{0:x} end: 0x{1:x}".format(
              dict['TEE_GOT_START'], dict['TEE_GOT_END']))
        print("relplt start: 0x{0:x} end: 0x{1:x}".format(
              dict['TEE_RELPLT_START'], dict['TEE_RELPLT_END']))
        print("reldyn start: 0x{0:x} end: 0x{1:x}".format(
              dict['TEE_RELDYN_START'], dict['TEE_RELDYN_END']))
        print("reladyn start: 0x{0:x} end: 0x{1:x}".format(
              dict['TEE_RELADYN_START'], dict['TEE_RELADYN_END']))
        print("dynsym start: 0x{0:x} end: 0x{1:x}".format(
          dict['TEE_DYNSYM_START'], dict['TEE_DYNSYM_END']))
        print("relaplt start: 0x{0:x} end: 0x{1:x}".format(
              dict['TEE_RELAPLT_START'], dict['TEE_RELAPLT_END']))
        print("gtdata start: 0x{0:x} end: 0x{1:x}".format(
              dict['GT_DATA_START'], dict['GT_DATA_END']))
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

        for index, imgfile in enumerate(t_filelist):
            offset = img_offset_list[index]
            f.seek(offset)
            print("place img_[{0}] at 0x{1:x}, imgfile:{2}".format(
                  index, offset, imgfile[img_path]))
            with open(imgfile[img_path], 'rb') as inf:
                f.write(inf.read())

        f.seek(kernel_offset)
        with open(kernel_file[img_path], 'rb') as inf:
            f.write(inf.read())


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
        krsapub_file = sys.argv[8]
    else:
        print("krsapub_file not exist:do not do encryption.")
        return
    if krsapub_file.startswith('krsa'):
        print("krsapub_file exist:go on do encryption.")
    else:
        print("krsapub_file not exist:do not do encryption.")
        return

    pwd_path = sys.path[0]
    wraptoolPath = pwd_path + '/wraptool_host/'

    tmpEncImgFilePath = wraptoolPath + 'tmp_enc/'
    if os.path.exists(tmpEncImgFilePath):
        shutil.rmtree(tmpEncImgFilePath)
    os.mkdir(tmpEncImgFilePath)

    #=== step 1: generate Krnd/IV, used to encrypimage
    print("step 1: generate Krnd/IV")
    krndFile = tmpEncImgFilePath + 'krnd.rnd'
    subprocess.run(["openssl", "rand", "-out", \
              krndFile, "32"], shell=False, check=True)
    rndFileSize = os.path.getsize(krndFile)
    rndFp = open(krndFile, 'rb')
    random = rndFp.read(rndFileSize)
    rndFp.close()
    randomStr = struct.unpack("32s", random)
    aesKey = binascii.b2a_hex(randomStr[0])

    #generate krndIV
    krndIVFile = tmpEncImgFilePath + 'krndIV.iv'
    subprocess.run(["openssl", "rand", "-out", \
              krndIVFile, "16"], shell=False, check=True)
    ivFileSize = os.path.getsize(krndIVFile)
    ivFp = open(krndIVFile, 'rb')
    iv = ivFp.read(ivFileSize)
    ivFp.close()
    ivStr = struct.unpack("16s", iv)
    aesRndIV = binascii.b2a_hex(ivStr[0])

    #generate enc image
    encImgFile = tmpEncImgFilePath + 'trustedcore_enc.img'
    aesStr = ''.join(map(chr, aesKey))
    aesRndStr = ''.join(map(chr, aesRndIV))
    subprocess.run(["openssl", "enc", "-aes-256-cbc", "-in", \
              img_name, "-out", encImgFile, \
              "-K", aesStr, "-iv", aesRndStr], shell=False, check=True)
    align_image(encImgFile)

    #=== step 2:generate En_Krnd/IV
    print("step 2: generate En_Krnd/IV")
    # pack Krnd and KrndIV to one file
    krndAllFile = tmpEncImgFilePath + 'krnd.all'
    rndFp = open(krndAllFile, 'ab')
    with open(krndFile, 'rb') as ivFp:
        rndFp.write(ivFp.read())
    with open(krndIVFile, 'rb') as ivFp:
        rndFp.write(ivFp.read())
    rndFp.close()

    #use rsa pubkey to encrypt Krnd/IV
    fastbootPubKeyFile = wraptoolPath + krsapub_file
    encRndFile = krndAllFile + '.sec'

    subprocess.run(["openssl", "rsautl", "-encrypt", "-pubin", \
              "-oaep", "-inkey", fastbootPubKeyFile, "-in", \
              krndAllFile, "-out", encRndFile], shell=False, check=True)
    #add En_Krnd/IV to trustedcore_enc_header.bin
    encImgHeaderFile = tmpEncImgFilePath + 'trustedcore_enc_header.bin'

    encRndFileSize = os.path.getsize(encRndFile)
    encRndFp = open(encRndFile, 'rb')
    encRndStr = encRndFp.read(encRndFileSize)
    encRndFp.close()

    img_magic_num = 0x5A5AA5A5
    img_format_version = 0x100
    img_reverse = [0, 0, 0, 0, 0, 0]
    z = struct.pack('<8I256s',
                    img_magic_num,
                    img_format_version,
                    img_reverse[0],
                    img_reverse[1],
                    img_reverse[2],
                    img_reverse[3],
                    img_reverse[4],
                    img_reverse[5],
                    encRndStr);
    encImgHeadFp = open(encImgHeaderFile, 'ab')
    encImgHeadFp.write(z)
    encImgHeadFp.close()

    #=== step 3:pack the ecrypt image
    print("step 3: pack the encryption image")
    encImgFinalFile = img_name
    no_encry_img = img_name + '.no_encrypt'
    subprocess.run(["cp", encImgFinalFile, \
              no_encry_img], shell=False, check=True)
    subprocess.run(["rm", encImgFinalFile], shell=False, check=True)
    resp = subprocess.run(["cp", encImgHeaderFile, \
              encImgFinalFile], shell=False, check=True)
    if resp.returncode == 0:
        print("suceed to cp trustedcore_enc_header.bin")
    else:
        raise RuntimeError("Failed to cp trustedcore_enc_header.bin.")

    #add encry img total size
    img_size = os.path.getsize(encImgFile)
    print("The size of image file is {0}".format(img_size))
    z = struct.pack('<1I',
                    img_size)
    encImgFp = open(encImgFinalFile, 'ab')
    encImgFp.write(z)
    encImgFp.close()

    #enc img header total 292 bytes
    header_size = os.path.getsize(encImgFinalFile)
    mod = header_size % 292
    if mod:
        header_size += 292 - mod
    with open(encImgFinalFile, 'ab+') as img:
        img.seek(0, 2)
        img.truncate(header_size)
    img.close()

    #add the encryt image append the header
    encImgFp = open(encImgFinalFile, 'ab')
    with open(encImgFile, 'rb') as ivFp:
        encImgFp.write(ivFp.read())
    encImgFp.close()

    #remove the temp dir
    if os.path.exists(tmpEncImgFilePath):
        shutil.rmtree(tmpEncImgFilePath)
    print("End: succeed to pack the encryption image")
    #=== end


if __name__ == '__main__':

    filelist = []
    internalTaskList = []
    dst_file = sys.argv[1]
    kernel_file = sys.argv[2],
    kernel_load_addr = int(sys.argv[3], 16)
    kernel_got_size = int(sys.argv[4], 16)
    filelist.append(kernel_file)

    rtosck_sym_head_args = sys.argv[5]
    rtosck_sym_item = rtosck_sym_head_args.split(',');
    rtosck_img_symtab_offset = int(rtosck_sym_item[0])
    rtosck_img_symtab_size = int(rtosck_sym_item[1], 16)
    rtosck_img_strtab_size = int(rtosck_sym_item[2]) - rtosck_img_symtab_size;

    compare_image = int(sys.argv[6], 10)
    image_load_addr = int(sys.argv[7], 16)

    for index, taskitem in enumerate(filelist):
        if index == 0 or index == 1:
            internalTaskList.append(taskitem)
            continue

    generate_header(internalTaskList, dst_file)
    align_image(dst_file)
    encryt_image(dst_file)
