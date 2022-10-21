# Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: makeflie for rmfs
# Create: 2019-08-20

CC = cc
CPPFLAGS :=
LDFLAGS :=

ifeq ($(USE_LIBC_32), y)
	ARCH = arm
endif
ifeq ($(USE_LIBC_64), y)
	ARCH = aarch64
endif

ifeq ($(TARGET_IS_ARM32),y)
	ARCH = arm
endif

include $(BUILD_CONFIG)/var.mk
CPPFLAGS += -I$(BUILD_TOOLS)/ramfsmkimg_host/include
CPPFLAGS += -I$(PREBUILD_HEADER)/host
CPPFLAGS += -I$(PREBUILD_HEADER)/ddk/hmapi
CPPFLAGS += -I$(PREBUILD_HEADER)/inner_sdk/hmapi
CPPFLAGS += -I$(TEE_SECUREC_DIR)/include
CPPFLAGS += -I$(PREBUILD_HEADER)/libc/hm
CPPFLAGS += -I$(PREBUILD_HEADER)/kernel/uapi
CPPFLAGS += -I$(PREBUILD_HEADER)/kernel/arch/arm/uapi
CPPFLAGS += -I$(PREBUILD_HEADER)
CPPFLAGS += -I$(PREBUILD_HEADER)/libc/arch/aarch64
CPPFLAGS += -I$(PREBUILD_HEADER)/libc
CPPFLAGS += -I$(PREBUILD_HEADER)/libc/arch/generic

CFLAGS :=

CPPFLAGS += -DDEBUG_USE_STDIO=1
CPPFLAGS += -DHM_HOST_BUILD=1

CFLAGS += -Wall -Wextra -Werror -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -fstack-protector-all
CFLAGS += -D__IN_KERNEL__

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
CFLAGS += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

LDFLAGS += -L$(OUTPUTDIR)/aarch64/obj/aarch64/libhwsecurec_host
LDFLAGS += -L/usr/lib/x86_64-linux-gnu
LDFLAGS += -lhwsecurec_host

C_SRCS := $(wildcard $(BUILD_TOOLS)/ramfsmkimg_host/src/*.c)
C_OBJS := $(addprefix $(BUILD_TOOLS)/ramfsmkimg_host/src/,$(notdir $(patsubst %.c,%.o,$(C_SRCS))))

# $(1)	Relative or absolute pathname to C file
define c_to_o
$(BUILD_TOOLS)/ramfsmkimg_host/src/$(patsubst %.c,%.o,$(notdir $(1))): $(1)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $$@ $$^
endef

install_headers:

all: stage
	mv $(BUILD_TOOLS)/ramfsmkimg_host/ramfsmkimg $(PREBUILD_TOOLS)/
	rm $(BUILD_TOOLS)/ramfsmkimg_host/src/main.o
	rm $(BUILD_TOOLS)/ramfsmkimg_host/.done-fetch
stage: build
fetch: $(BUILD_TOOLS)/ramfsmkimg_host/.done-fetch

$(BUILD_TOOLS)/ramfsmkimg_host/.done-fetch:
	mkdir -p $(BUILD_TOOLS)/ramfsmkimg_host
	touch $@

build: $(BUILD_TOOLS)/ramfsmkimg_host/.done-fetch $(BUILD_TOOLS)/ramfsmkimg_host/ramfsmkimg

$(BUILD_TOOLS)/ramfsmkimg_host/ramfsmkimg: $(C_OBJS)
	pwd
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(foreach c_file,$(C_SRCS),$(eval $(call c_to_o,$(c_file))))

clean:

.PHONY: fetch build
