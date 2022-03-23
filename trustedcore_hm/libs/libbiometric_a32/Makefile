# Target is a TA app
MODULE := libbiometric_a32.a

libbiometric_a32_c_files += $(wildcard src/*.c)

#c-flags += -Wno-unused-parameterc-flags
c-flags += -fno-builtin
#c-flags += -Wall -Wextra
c-flags += -DCC_DRIVER=1
c-flags += -DRESERVE_TA_PERM
c-flags += -Wextra
c-flags += -Wdate-time
c-flags += -Wfloat-equal
c-flags += -Wshadow
c-flags += -Wformat=2
c-flags += -O2

#c-flags += -DCC_DRIVER -Wall -Wno-parentheses -Wno-unused-parameter
c-flags += -I$(TOPDIR)/libs/libbiometric_a32/include
c-flags += -I$(TOPDIR)/libs/libmspcore_a32/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
c-flags += -DCONFIG_HISI_BIOMETRIC
endif

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
