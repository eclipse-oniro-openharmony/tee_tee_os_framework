# Targets
MODULE := libramfs_host.a
TARGET_IS_HOST = y

flags += -Wall -Wextra
# Source files required to build the target
libramfs_host_c_files := $(wildcard src/*.c)

inc-flags += -I$(TOPDIR)/libs/libramfs_host/include
inc-flags += -I$(TOPDIR)/libs/libvfs_host/include
inc-flags += -I$(PREBUILD_HEADER)/libc/arch
inc-flags += -I$(PREBUILD_HEADER)/libc/hm

include $(TOPDIR)/mk/lib-common.mk

override CC=cc
override AR=ar
override flags := -Wall -std=gnu99 -DHM_BUILD_TARGET_HOST
override c-flags :=

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
override flags += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif
