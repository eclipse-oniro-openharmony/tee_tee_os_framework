# huk lib compile rule, modified by pengshuai@huawei.com
# Copyright Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

# Targets
TARGETS := libhuk${TARG}.a

CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/tee_internal_huk_api.c))
CFILES += $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/huk_service_msg_call.c))

include $(HM_COMMON)/common.mk
include $(HM_COMMON)/common-nwe-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk

CPPFLAGS += -I$(PWD)/libs/teelib/libhuk/include
CPPFLAGS += -I$(PWD)/libs/teelib/libhuk/src/huk_service
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(PWD)/libs/syslib/libipc/include
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include
CPPFLAGS += -I$(TEELIB)/libteeconfig/include/TEE_ext
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(PWD)/libs/syslib/libsyscalls/include
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libssa/include
