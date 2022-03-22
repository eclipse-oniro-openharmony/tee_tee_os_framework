# Target is a TA app
MODULE := librot_a32.a

librot_a32_c_files += $(wildcard src/*.c)

c-flags += -fno-builtin
c-flags += -DCC_DRIVER=1
c-flags += -DRESERVE_TA_PERM
c-flags += -Wextra
c-flags += -Wdate-time
c-flags += -Wfloat-equal
c-flags += -Wshadow
c-flags += -Wformat=2
c-flags += -O2

c-flags += -I$(TOPDIR)/libs/librot_a32/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
c-flags += -I$(TOPDIR)/libs/libmspcore_a32/include
ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
    c-flags += -DCONFIG_GENERIC_ROT
endif

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
