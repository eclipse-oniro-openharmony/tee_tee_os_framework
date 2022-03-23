# Targets
MODULE := libvfs_host.a
TARGET_IS_HOST = y

#flags += -Wall -Wextra

# Source files required to build the target
libvfs_host_c_files := $(wildcard src/*.c)


inc-flags += -I$(TOPDIR)/libs/libvfs_host/include
#inc-flags += -I$(PREBUILD_HEADER)/libc/arch/aarch64
inc-flags += -I$(PREBUILD_HEADER)/libc/hm
inc-flags += -I$(PREBUILD_HEADER)

override CC=cc
override AR=ar
override flags := -Wall -Wextra -Werror -DHM_BUILD_TARGET_HOST
override c-flags :=
override GENERAL_OPTIONS :=

ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
override flags += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
endif

include $(TOPDIR)/mk/lib-common.mk
