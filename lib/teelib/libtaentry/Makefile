# libtaentry compile rule, modified by y00416812
# Copyright Huawei Technologies Co., Ltd. 2010-2020. All rights reserved.

TARGETS := libtaentry${TARG}.a

include $(HM_COMMON)/common-nwe-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk

ALL_CFILE := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/*.c))
EXCEPT_CFILE := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/client_auth_user_name.c))
CFILES := $(filter-out  $(EXCEPT_CFILE), $(ALL_CFILE))

CPPFLAGS += -I$(PWD)/libs/syslib/libhongmeng/include
CPPFLAGS += -I$(PWD)/libs/syslib/libipc/include
CPPFLAGS += -I$(PWD)/libs/syslib/libteemem/include
CPPFLAGS += -I$(PWD)/ext_apps/hm-apps/trustedcore_hm/sys_libs/libteeconfig/include/TEE_ext
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(PWD)/libs/teelib/libcrypto/include
CPPFLAGS += -I$(PWD)/ext_apps/hm-apps/framework/tarunner/src

ifeq ($(CONFIG_TEST_CA_CHECK),y)
    CPPFLAGS += -I$(PWD)/ext_apps/hm-apps/trustedcore_hm/sys_libs/libteeconfig/src/tee_test_config
endif

include $(HM_COMMON)/common.mk
