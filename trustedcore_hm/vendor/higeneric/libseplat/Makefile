# MODULE is a lib
MODULE := libseplat.a

libseplat_c_files += $(wildcard src/*.c)

c-flags += -fno-builtin

c-flags += -I$(TOPDIR)/vendor/higeneric/libseplat/include
c-flags += -I$(TOPDIR)/vendor/higeneric/libvendor_shared/src
c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/seplat
ifeq ($(chip_type),es)
c-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)_es
else
c-flags += -I$(TOPDIR)/../../../../../vendor/hisi/ap/platform/$(TARGET_BOARD_PLATFORM)
endif

c-flags += -Werror
c-flags += -Wextra
c-flags += -Wdate-time
c-flags += -Wfloat-equal
c-flags += -Wshadow
c-flags += -Wformat=2
c-flags += -O2

ifeq ($(seplat), london)
c-flags += -DCONFIG_SEPLAT_FEATURE
endif # london

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)

