#
# Copyright 2017, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

libs-$(CONFIG_LIB_BASEAGENT) += libagent_base libagent_base_a32 
libagent_base: common libc
libagent_base_a32: common libc_a32
