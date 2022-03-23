# Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: Makefile for rmfs
# Create: 2019-08-20

KERNEL = $(PWD)/kernel
CC =cc

include $(TOPDIR)/mk/var.mk

CPPFLAGS :=
CFLAGS :=
LDFLAGS :=

TARGET_IS_HOST = y

CPPFLAGS += -I$(TOPDIR)/libs/libvfs_host/include
CPPFLAGS += -I$(TOPDIR)/libs/ramfsdump_host/include
CPPFLAGS += -I$(PREBUILD_HEADER)/ddk/hmapi
CPPFLAGS += -I$(PREBUILD_HEADER)/libc/hm
CPPFLAGS += -I$(PREBUILD_HEADER)/kernel/uapi
CPPFLAGS += -I$(PREBUILD_HEADER)
CPPFLAGS += -I$(PREBUILD_HEADER)/libc
CPPFLAGS += -I$(PREBUILD_HEADER)/libc/arch/aarch64
CPPFLAGS += -I$(TOPDIR)/libs/libramfs_host/include


#CPPFLAGS += -I$(PWD)/libs/syslib/libc/include/arch/aarch64
#CPPFLAGS += -I$(PWD)/libs/syslib/libutils/include

CPPFLAGS +=	-DDEBUG_USE_STDIO=1
CPPFLAGS +=	-DHM_HOST_BUILD=1

CFLAGS +=	-Wall -Wextra -Werror -fPIC -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now  -fstack-protector-all

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
CFLAGS += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

LDFLAGS += -L$(OUTPUTDIR)/aarch64/obj/aarch64/libramfs_host
LDFLAGS += -L$(OUTPUTDIR)/aarch64/obj/aarch64/libvfs_host
LDFLAGS += -L$(OUTPUTDIR)/aarch64/obj/aarch64/libhwsecurec_host
LDFLAGS += -L/usr/lib/x86_64-linux-gnu
LDFLAGS += -lramfs_host
LDFLAGS += -lvfs_host
LDFLAGS += -lhwsecurec_host

C_SRCS :=	$(wildcard $(TOPDIR)/libs/ramfsdump_host/src/*.c)
C_OBJS :=	$(addprefix $(TOPDIR)/libs/ramfsdump_host/src/,$(notdir $(patsubst %.c,%.o,$(C_SRCS))))

# $(1)	Relative or absolute pathname to C file
define c_to_o

$(TOPDIR)/libs/ramfsdump_host/src/$(patsubst %.c,%.o,$(notdir $(1))): $(1)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $$@ $$^
endef

install_headers:

all: build
	mv $(TOPDIR)/libs/ramfsdump_host/ramfsdump $(PREBUILD_TOOLS)/
	rm $(TOPDIR)/libs/ramfsdump_host/src/main.o
	rm $(TOPDIR)/libs/ramfsdump_host/.done-fetch

fetch: $(TOPDIR)/libs/ramfsdump_host/.done-fetch

$(TOPDIR)/libs/ramfsdump_host/.done-fetch:
	mkdir -p $(TOPDIR)/libs/ramfsdump_host
	touch $@

build: $(TOPDIR)/libs/ramfsdump_host/.done-fetch $(TOPDIR)/libs/ramfsdump_host/ramfsdump

$(TOPDIR)/libs/ramfsdump_host/ramfsdump: $(C_OBJS)
	pwd
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(foreach c_file,$(C_SRCS),$(eval $(call c_to_o,$(c_file))))

clean:

.PHONY: fetch build
