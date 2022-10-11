#
# Copyright 2019, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
TARGETS := libssa${TARG}.a


CFILES   := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/*.c))
include $(HM_COMMON)/common.mk
include $(HM_COMMON)/common-nwe-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk
CPPFLAGS += -I$(PWD)/libs/teelib/libssa/include
CPPFLAGS += -I$(TEELIB)/libteemem/include
CPPFLAGS += -I$(TEELIB)/libcrypto_hal/include
CPPFLAGS += -I$(TEELIB)/libcrypto/include
CPPFLAGS += -I$(TEELIB)/libteeos/src/tee
CPPFLAGS += -I$(PWD)/libs/syslib/libipc/include
CPPFLAGS += -I$(TEELIB)/libtimer/include
CPPFLAGS += -I$(PWD)/libs/teelib/libse/include
CPPFLAGS += -I$(TEELIB)/libteeos/include/legacy
CPPFLAGS += -I$(TEELIB)/libteeos/include
CPPFLAGS += -I$(PWD)/libs/teelib/libhuk/include
CPPFLAGS += -I$(PWD)/libs/syslib/libipc/include # msg_ops.h
CPPFLAGS += -I$(TEELIB)/libteeos/include/tee # tee_inner_uuid.h
CPPFLAGS += -I$(TEELIB)/libteeagentcommon_client/include

CFLAGS += -DOPENSSL_ENABLE
A32_CFLAGS += -DOPENSSL_ENABLE
