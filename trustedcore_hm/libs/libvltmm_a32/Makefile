# Target is a TA app
MODULE := libvltmm_a32.a

libvltmm_a32_c_files += $(wildcard src/*.c)

c-flags += -Wno-unused-parameter
c-flags += -fno-builtin
c-flags += -Wall
c-flags += -DCC_DRIVER=1
c-flags += -DRESERVE_TA_PERM


#c-flags += -DCC_DRIVER -Wall -Wno-parentheses -Wno-unused-parameter
c-flags += -I$(TOPDIR)/libs/libvltmm/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/libc_32/hm
ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
ifeq ($(chip_type), es)
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore_es
else
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/baltimore
endif
	c-flags += -DTEE_SUPPORT_VLTMM_SRV
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), laguna), )
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/laguna
	c-flags += -DTEE_SUPPORT_VLTMM_SRV
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), burbank), )
	c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/include/platform/burbank
	c-flags += -DTEE_SUPPORT_VLTMM_SRV
endif

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
