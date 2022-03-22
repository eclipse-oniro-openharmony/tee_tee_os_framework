# Target is a TA app
MODULE := libsec_flash_client.a

libsec_flash_client_c_files += $(wildcard src/*.c)

#c-flags += -Wno-unused-parameterc-flags
c-flags += -fno-builtin

#c-flags += -Wall -Werror -Wno-parentheses -Wno-unused-parameter
c-flags += -I$(TOPDIR)/libs/libsec_flash_client/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
c-flags += -I$(TOPDIR)/vendor/higeneric/libvendor_shared/src

c-flags += -Wextra
c-flags += -Wdate-time
c-flags += -Wfloat-equal
c-flags += -Wshadow
c-flags += -Wformat=2
c-flags += -O2

ifneq ($(filter $(TARGET_BOARD_PLATFORM), kirin990), )
    c-flags += -DCONFIG_HISI_SECFLASH
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
    c-flags += -DHISI_MSP_SECFLASH
endif

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
