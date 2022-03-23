# libcpio compile dependencies libraries
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

libs-$(CONFIG_LIB_CPIO) += libcpio
libcpio: common
libs-$(CONFIG_LIB_CPIO_A32) += libcpio_a32
libcpio_a32: common
