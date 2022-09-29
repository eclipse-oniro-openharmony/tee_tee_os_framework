# libtaentry compile rule, modified by y00416812
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

MODULE := libtaentry${TARG}.a

CFILES := $(wildcard src/*.c)

CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeconfig/include/TEE_ext
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(FRAMEWORK_PATH)/tarunner/src
CPPFLAGS += -I$(TEELIB)/libcrypto/include

ifeq ($(CONFIG_TEST_CA_CHECK),y)
    CPPFLAGS += -I$(TOPDIR)/sys_libs/libteeconfig/src/tee_test_config
endif

include $(TOPDIR)/mk/lib-common.mk
