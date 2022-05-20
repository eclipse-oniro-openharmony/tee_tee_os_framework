# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# Targets
TARGETS := $(notdir $(SOURCE_DIR)).elf

TA_NAME := $(notdir $(SOURCE_DIR))
ifeq ($(CONFIG_ARCH_AARCH64),y)
ARCH = aarch64
else
ARCH = arm
TARGET_IS_ARM32 = y
endif

include $(HM_COMMON)/common-nwe-flags.mk
INCLUDE_DIRS += $(PWD)/libs/syslib/libmmgr/include
INCLUDE_DIRS += $(PWD)/libs/syslib/libpathmgr/include
INCLUDE_DIRS += $(PWD)/libs/teelib/libteeos/include/TEE
INCLUDE_DIRS += $(PWD)/libs/teelib/libteeos/include/legacy
INCLUDE_DIRS += $(PWD)/libs/syslib/libhwi/include
INCLUDE_DIRS += $(PWD)/libs/syslib/libhmlog/include
INCLUDE_DIRS += $(PWD)/libs/syslib/libcrt0/include
INCLUDE_DIRS += $(PWD)/libs/syslib/libsyscalls/include

CPPFLAGS += -I$(SOURCE_DIR)/include

include $(HM_COMMON)/common-flags.mk
include $(HM_COMMON)/libc-flags.mk
include $(HM_COMMON)/bootstrap-flags.mk

ifneq ($(O),)
OUTPUT_LIBDIR := $(O)/$(ARCH)/libs
else
OUTPUT_LIBDIR := $(srctree)/../tee_os_framework/trustedcore_hm/output/$(ARCH)/libs
endif

LDFLAGS += -u _hm_start -z noexecstack -L$(OUTPUT_LIBDIR)

ifeq (${CONFIG_ENABLE_XOM},y)
ifeq ($(CONFIG_ARCH_AARCH64),y)
LDFLAGS += -execute-only
endif
endif

# Source files required to build the target
CFILES :=  $(patsubst $(SOURCE_DIR)/%,%,$(wildcard $(SOURCE_DIR)/src/*.c))

HDRFILES := $(wildcard $(SOURCE_DIR)/include/*)

$(BUILD_DIR)/$(TA_NAME): $(BUILD_DIR)/$(TARGETS)
	cp $< $@

# Libraries
ifeq ($(CONFIG_ARCH_AARCH64),y)
LIBS := c hongmeng mmgr syscalls crt0 pathmgr debug ipc hwsecurec irqmgr
else
LIBS := c_a32 hongmeng_a32 mmgr_a32 syscalls_a32 crt0_a32 pathmgr_a32 debug_a32 ipc_a32 hwsecurec_a32 irqmgr_a32
endif
ENTRY_POINT := _hm_start

ifeq ($(CONFIG_ARCH_AARCH64),y)
USE_LIBC_64 = y
else
USE_LIBC_32 = y
endif
include $(HM_COMMON)/common.mk

CFLAGS += -fvisibility=hidden

${COMPONENTS}:
	false

ifeq ($(CONFIG_SSA_EMBEDDED),y)
CFLAGS += -DSSA_EMBEDDED
endif
