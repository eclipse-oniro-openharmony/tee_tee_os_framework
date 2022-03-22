# Target is a lib
MODULE := libweaver_a32.a

libweaver_a32_c_files += $(wildcard src/*.c)

#c-flags += -Wno-unused-parameterc-flags
c-flags += -fno-builtin
c-flags += -Wall  -Wextra
c-flags += -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -O2
c-flags += -DRESERVE_TA_PERM
c-flags += -DTA_SLOG_LEVEL=2
ifneq ($(filter $(TARGET_BOARD_PLATFORM), baltimore), )
    c-flags += -DSUPPORT_MSP_WEAVER
#   c-flags += -DSUPPORT_DYN_WEAVER
    c-flags += -DSUPPORT_STK_WEAVER
endif

#c-flags += -DCC_DRIVER -Wall -Wno-parentheses -Wno-unused-parameter
c-flags += -I$(TOPDIR)/libs/libweaver_a32/include
c-flags += -I$(TOPDIR)/libs/libsec_flash_client_a32/src
c-flags += -I$(TOPDIR)/libs/libmspcore_a32/include

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
flags += $(TRUSTEDCORE_PLATFORM_FLAGS)
