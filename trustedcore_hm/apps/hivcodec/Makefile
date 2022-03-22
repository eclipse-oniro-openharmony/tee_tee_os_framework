# TARGET is a TA app
TARGET := hivcodec.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

ifneq ($(TARGET_BOARD_PLATFORM), baltimore)
hivcodec_c_files += $(wildcard src/task_hi_vcodec/hi_vcodec_task_hivna.c)
endif
hivcodec_c_files += $(wildcard src/vcodec_drv.c)

ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
hivcodec_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
hivcodec_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
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
