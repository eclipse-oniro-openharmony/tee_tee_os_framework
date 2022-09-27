#
# Copyright 2017, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

libs-$(CONFIG_LIB_HWSECUREC) += libagent libagent_a32 

libagent: common \
    libteeos     \
    libc

libagent_a32: common \
    libteeos_a32     \
    libc_a32
