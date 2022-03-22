# libtee_cmscbb compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.

MODULE := libtee_cmscbb$(TARG).a

inc-flags += -I$(TOPDIR)/sys_libs/libtee_cmscbb/include
inc-flags += -I$(TOPDIR)/thirdparty/huawei/libcmscbb/cmscbb/include
inc-flags += -I$(PREBUILD_HEADER)/openssl

# Source files required to build the target
libtee_cmscbb_c_files += $(wildcard src/*.c)

ifeq ($(CONFIG_TA_CMS_SIGNATURE),y)
ifeq (${TARG}, )
flags += -DSUPPORT_UPDATE_CRL
endif
endif

include $(TOPDIR)/mk/lib-common.mk
