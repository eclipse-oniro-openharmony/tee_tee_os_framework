#
# Copyright 2019, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

libs-y += libcrypto libcrypto_a32

libcrypto: libhwsecurec \
    libc \
    hm-app-headers
libcrypto_a32: libhwsecurec_a32 \
    libc_a32 \
    hm-app-headers
