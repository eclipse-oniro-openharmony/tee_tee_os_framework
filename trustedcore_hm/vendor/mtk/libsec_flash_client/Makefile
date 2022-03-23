# Target is a TA app
MODULE := libsec_flash_client${TARG}.a

libsec_flash_client_c_files += $(wildcard src/*.c)

c-flags += -fno-builtin

include $(TOPDIR)/mk/lib-common.mk

# Header files/directories this library provides
EXPORT_HDRS := $(wildcard include/*)
