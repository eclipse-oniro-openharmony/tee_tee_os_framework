# libcpio compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

TARGETS := libcpio${TARG}.a

include $(HM_COMMON)/common-nwe-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk

# Source files required to build the target
CFILES := $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/*.c))
CPPFLAGS += -I$(srctree)/../tee_os_framework/trustedcore_hm/sys_libs/libcpio/include

NO_KASAN = y
include $(HM_COMMON)/common.mk

