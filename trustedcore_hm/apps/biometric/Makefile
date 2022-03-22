# Target is a TA app
TARGET := biometric.elf

biometric_c_files += $(wildcard src/*.c)

c-flags += -Wextra
c-flags += -Wdate-time
c-flags += -Wfloat-equal
c-flags += -Wshadow
c-flags += -Wformat=2
c-flags += -O2

# Libraries
LIBS := teeagentcommon${TARG} mspcore_a32

#c-flags += -DCC_DRIVER -Wall -Wno-parentheses -Wno-unused-parameter
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src
c-flags += -I$(TOPDIR)/platform/common/tee_config
c-flags += -I$(TOPDIR)/libs/libbiometric_a32/include
c-flags += -I$(TOPDIR)/libs/libmspcore_a32/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include

include $(TOPDIR)/mk/ta-common.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
TA_LDFLAGS += -s
endif
