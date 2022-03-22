# TARGET is a TA app
TARGET := hivcodec_sr.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

ifeq ($(TARGET_BOARD_PLATFORM), baltimore)
hivcodec_sr_c_files += $(wildcard src/hi_vcodec_task_hivna_ta.c)
endif

ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
hivcodec_sr_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
hivcodec_sr_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=

include $(TOPDIR)/mk/ta-common.mk

CFLAGS += -Wall -Wextra -Wdate-time
c-flags += -fno-common
LDFLAGS += -Wl,-Bsymbolic
LDFLAGS += -Wl,--no-undefined
c-flags += -DTEE_SUPPORT_RPMB_DEVICE
c-flags += -DTEE_SUPPORT_HIVCODEC
ifeq (,$(filter $(TARGET_BOARD_PLATFORM), hi3660))
c-flags += -DTEE_SUPPORT_TZMP2
endif
