#
# Copyright 2022, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

libs-y += libpermission_service libpermission_service_a32

libpermission_service: libhwsecurec \
    libc
libpermission_service_a32: libhwsecurec_a32 \
    libc_a32
