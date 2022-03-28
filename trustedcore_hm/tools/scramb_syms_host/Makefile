# Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: Makefile for rmfs
# Create: 2019-08-20

CC = cc

TARGET_IS_HOST = y

CFLAGS :=
CFLAGS += -Wall -Wextra -Werror -fPIC -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -fstack-protector-all -fPIE

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
CFLAGS += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

ifdef CONFIG_DEBUG_BUILD
CFLAGS += -ggdb
endif

ifeq ($(USE_LIBC_32), y)
	ARCH = arm
endif
ifeq ($(USE_LIBC_64), y)
	ARCH = aarch64
endif

ifeq ($(TARGET_IS_ARM32),y)
	ARCH = arm
endif

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

CPPFLAGS += -I$(TEE_SECUREC_DIR)/include
CPPFLAGS += -I/usr/local/ssl/include
LDFLAGS += -L/usr/local/ssl/lib -lcrypto -ldl

ifeq ($(ARCH),arm)
LDFLAGS += -L$(OUTPUTDIR)/$(ARCH)/obj/$(ARCH)/libhwsecurec_host
else
LDFLAGS += -L$(OUTPUTDIR)/$(ARCH)/obj/$(ARCH)/libhwsecurec_host
endif

LDFLAGS += -lhwsecurec_host
LDFLAGS += -L/usr/lib/x86_64-linux-gnu

C_SRCS :=	$(wildcard $(TOPDIR)/tools/scramb_syms_host/*.c)
C_OBJS :=	$(addprefix $(BUILD_DIR)/,$(notdir $(patsubst %.c,%.o,$(C_SRCS))))

# $(1)	Relative or absolute pathname to C file
define c_to_o
$(BUILD_DIR)/$(patsubst %.c,%.o,$(notdir $(1))): $(1)
	test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $$@ $$^
endef

all:$(PREBUILD_TOOLS)/scramb_syms_host
install_headers:

$(PREBUILD_TOOLS)/scramb_syms_host: $(BUILD_DIR)/scramb_syms_host
	pwd
	test -d $(dir $@) || mkdir -p $(dir $@)
	echo "cp scramb"
	cp -f $(BUILD_DIR)/scramb_syms_host $(PREBUILD_TOOLS)/scramb_syms_host
	rm $(BUILD_DIR)/scramb_syms.o

$(BUILD_DIR)/scramb_syms_host: $(C_OBJS)
	pwd
	test -d $(dir $@) || mkdir -p $(dir $@)
	echo "build scramb"
	echo "C_SRCS"  $(C_SRCS)
	echo "C_OBJS" $(C_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(foreach c_file,$(C_SRCS),$(eval $(call c_to_o,$(c_file))))

HOSTLOADLIBES_scramb_syms := -lcrypto
hostprogs-y	:= scramb_syms_host
always		:= $(hostprogs-y)

clean-files += *.cmd
no-clean-files += scramb_syms_host
