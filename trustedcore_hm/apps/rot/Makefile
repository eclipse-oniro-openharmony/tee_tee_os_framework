# Target is a TA app
TARGET := rot.elf

rot_c_files += $(wildcard src/*.c)

c-flags += -Wall -Wextra -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -O2

# Libraries
LIBS :=  teeagentcommon${TARG}

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src
c-flags += -I$(TOPDIR)/libs/librot/include
c-flags += -I$(TOPDIR)/libs/libmspcore_a32/include
c-flags += -I$(TOPDIR)/platform/common/tee_config
c-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include

include $(TOPDIR)/mk/ta-common.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
