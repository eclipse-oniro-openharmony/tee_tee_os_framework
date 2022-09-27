#
# Copyright 2017, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

libs-$(CONFIG_LIB_TEEOS) += libteeos libteeos_a32
libteeos : common \
    libhwsecurec \
    libc         \
    libmmgr      \
    libac        \
    hm-app-headers \

libteeos_a32 : common \
    libhwsecurec_a32 \
    libc_a32         \
    libmmgr_a32      \
    libac_a32        \
    hm-app-headers \
