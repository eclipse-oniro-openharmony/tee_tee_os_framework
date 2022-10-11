#
# Copyright 2019, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

libs-y += libssa libssa_a32

libssa: libhwsecurec \
        libc \
        hm-app-headers
libssa_a32: libhwsecurec_a32 \
            libc_a32 \
            hm-app-headers
