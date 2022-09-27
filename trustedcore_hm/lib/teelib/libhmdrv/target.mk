# libhmdrv target compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.

libs-$(CONFIG_LIB_HMDRV) += libhmdrv libhmdrv_a32

libhmdrv : common \
    libhongmeng   \
    libsyscalls   \
    libipc        \
    libac-hdr     \
    libc
libhmdrv_a32: common \
    libhongmeng_a32  \
    libsyscalls_a32  \
    libipc_a32       \
    libac_a32-hdr    \
    libc_a32
