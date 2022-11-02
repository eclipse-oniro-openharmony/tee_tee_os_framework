# huk lib compile rule, modified by pengshuai@huawei.com
# Copyright Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

libs-y += libhuk libhuk_a32

libhuk: libhwsecurec \
        libc
libhuk_a32: libhwsecurec_a32 \
            libc_a32
