# MODULE is a lib
MODULE := libmspcore.a

libmspcore_c_files += $(wildcard src/*.c)

c-flags += -fno-builtin

c-flags += -I$(TOPDIR)/libs/libmspcore/include
c-flags += -I$(TOPDIR)/libs/libart/include
c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/kirin/eSE/hisee
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
c-flags += -I$(TOPDIR)/libs/libsec_flash_client/src
c-flags += -I$(TOPDIR)/vendor/higeneric/libvendor_shared/src

c-flags += -Wextra
c-flags += -Wdate-time
c-flags += -Wfloat-equal
c-flags += -Wshadow
c-flags += -Wformat=2
c-flags += -O2

include $(TOPDIR)/mk/lib-common.mk

ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
c-flags += -DCONFIG_HISI_MSPC
endif

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)

