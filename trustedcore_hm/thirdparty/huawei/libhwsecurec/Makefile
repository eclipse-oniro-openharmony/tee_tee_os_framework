#
# Copyright 2017, Huawei Co. Ltd.
#
# See "HUAWEI_LICENSE" for details.
#

# Targets
MODULE := libhwsecurec${TARG}.a
ifeq (${TARG}, _a32)
A32_CFLAGS += -Wall -Wextra -Werror -DSECUREC_MEMSET_INDIRECT_USE=0
endif

CFLAGS += -Wall -Wextra -Werror -DSECUREC_MEMSET_INDIRECT_USE=0
CFLAGS += -fstack-protector-strong
ifeq ($(USE_LIBC_32), y)
	ARCH = arm
endif
ifeq ($(USE_LIBC_64), y)
	ARCH = aarch64
endif

ifeq ($(TARGET_IS_ARM32),y)
	ARCH = arm
endif

TOPDIR = $(CURDIR)/../../..
include $(TOPDIR)/mk/var.mk

flags = -Wall -Wextra -Werror -DSECUREC_MEMSET_INDIRECT_USE=0 -fstack-protector-strong -fPIC
flags += -DARCH_ARM -DAARCH64 -D__KERNEL_64__ -DARMV8_A -DARM_CORTEX_A53 -DKIRIN
flags += -DARM_PAE=1 -DHAVE_AUTOCONF -include$(PREBUILD_DIR)/headers/autoconf.h
flags += -nodefaultlibs -nostdinc -fno-omit-frame-pointer
flags += -fno-builtin-aligned_alloc \
	-fno-builtin-alloca \
	-fno-builtin-calloc \
	-fno-builtin-fwrite	\
	-fno-builtin-fread	\
	-fno-builtin-fseek	\
	-fno-builtin-fclose	\
	-fno-builtin-malloc \
	-fno-builtin-memcpy	\
	-fno-builtin-memcmp	\
	-fno-builtin-memset	\
	-fno-builtin-memmove \
	-fno-builtin-realloc \
	-fno-builtin-strncmp \
	-fno-builtin-strlen \
	-fno-builtin-strncpy \
	-fno-builtin-strncat \
	-fno-builtin-posix_memalign \
	-fno-builtin-printf \
	-fno-builtin-snprintf \
	-fno-builtin-vsnprintf \
	-fno-builtin-fwrite_unlocked \
	-fno-builtin-memchr \
	-fno-builtin-strcspn \
	-fno-builtin-strspn \
	-fno-builtin-bcmp \
	-fno-builtin-bcopy \
	-fno-builtin-bzero \
	-fno-builtin-strncasecmp \
	-fno-builtin-stpncpy \
	-fno-builtin-strndup \
    -fno-builtin-strlcat \
    -fno-builtin-strlcat \
    -fno-builtin-strlcpy \
    -fno-builtin-strxfrm \
    -fno-builtin-strlcat \
    -fno-builtin-strlcpy \
    -fno-builtin-strxfrm \
    -fno-builtin-strlcat \
    -fno-builtin-strlcpy \
    -fno-builtin-strxfrm \
    -fno-builtin-strlcat \
    -fno-builtin-strlcpy

flags += -DCC_IDENTIFICATION

TEEOSDIR = $(CURDIR)/../../../../../tee_os_kernel
CPPFLAGS += -I$(STAGE_DIR)/include/debug
CPPFLAGS += -I$(PREBUILD_LIBC_INC)
inc-flags += -I$(PREBUILD_LIBC_INC) \
		-I$(PREBUILD_LIBC_INC)/hm \
		-I$(PREBUILD_LIBC_INC)/arch/generic \
		-I$(PREBUILD_LIBC_INC)/arch/$(ARCH) \
		-I$(PREBUILD_HEADER)/gen/arch/$(ARCH)

inc-flags += -I$(TEE_SECUREC_DIR)/include
# stdlib headers for hm-apps source
opensource = $(shell if [ -d $(TOPDIR)/../open_source ]; then echo "exist"; else echo "noexist"; fi)
ifeq ("$(opensource)", "exist")
	inc-flags += -I$(TOPDIR)/../open_source/musl/include/
	inc-flags += -I$(TOPDIR)/../open_source/musl/arch/$(ARCH)/
	inc-flags += -I$(TOPDIR)/../open_source/musl/arch/generic/
endif
# c-flags += $(CFLAGS)
# Source files required to build the target
CFILES := $(TEE_SECUREC_DIR)/src/memcpy_s.c \
          $(TEE_SECUREC_DIR)/src/memmove_s.c \
          $(TEE_SECUREC_DIR)/src/memset_s.c \
          $(TEE_SECUREC_DIR)/src/securecutil.c \
          $(TEE_SECUREC_DIR)/src/snprintf_s.c \
          $(TEE_SECUREC_DIR)/src/strcat_s.c \
          $(TEE_SECUREC_DIR)/src/strcpy_s.c \
          $(TEE_SECUREC_DIR)/src/strncat_s.c \
          $(TEE_SECUREC_DIR)/src/strncpy_s.c \
          $(TEE_SECUREC_DIR)/src/strtok_s.c \
          $(TEE_SECUREC_DIR)/src/vsnprintf_s.c \
          $(TEE_SECUREC_DIR)/src/secureprintoutput_a.c
libhwsecurec_c_files := $(CFILES)

ifeq ($(PLATFORM_DIR),)
	PLATFORM_DIR = $(TOPDIR)/platform
endif

ifneq ($(O),)
OUTPUTDIR := $(O)
else
OUTPUTDIR := $(TOPDIR)/output
endif

ifeq ($(HM_PLATFORM),)
HM_PLATFORM := kirin
endif

ifeq ($(HM_SDK_VER),)
HM_SDK_VER := hm-teeos-release
endif

VER := @
include $(TOPDIR)/mk/cfg.mk
include $(TOPDIR)/mk/toolchain.mk
include $(TOPDIR)/mk/common.mk
