# Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: Makefile for xom
# Create: 2020-09-10

CC = cc

TARGET_IS_HOST = y

CFLAGS :=
CFLAGS += -Wall -Wextra -Werror -fPIC -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -fstack-protector-all -fPIE

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
CFLAGS += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

ARCH = arm

TOPDIR = $(CURDIR)/../..
ifeq ($(PLATFORM_DIR),)
	PLATFORM_DIR = $(TOPDIR)/platform
endif

ifneq ($(O),)
OUTPUTDIR := $(O)
else
OUTPUTDIR := $(TOPDIR)/output
endif

ifeq ($(HM_SDK_VER),)
HM_SDK_VER := hm-teeos-release
endif
MODULE_FOLDER := $(shell basename $(CURDIR))

include $(TOPDIR)/mk/var.mk

C_SRCS :=	$(wildcard $(TOPDIR)/tools/xom/*.c)
CPPFLAGS += -I$(TEE_SECUREC_DIR)/include
LDFLAGS += -L$(OUTPUTDIR)/$(ARCH)/libs -lhwsecurec_host

define c_to_o
$(BUILD_DIR)/$(patsubst %.c,%.o,$(notdir $(1))): $(1)
	test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $$@ $$^
endef

all:$(CURDIR)/xom
install_headers:

$(CURDIR)/xom: $(C_SRCS)
	pwd
	test -d $(dir $@) || mkdir -p $(dir $@)
	echo "build xom"
	echo "C_SRCS"  $(C_SRCS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

#$(foreach c_file,$(C_SRCS),$(eval $(call c_to_o,$(c_file))))

hostprogs-y	:= xom
always		:= $(hostprogs-y)

clean-files += *.cmd
no-clean-files += xom
