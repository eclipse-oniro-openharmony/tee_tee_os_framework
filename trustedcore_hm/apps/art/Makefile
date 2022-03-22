# Target is a TA app
TARGET := art.elf

art_c_files += $(wildcard src/*.c)

c-flags += -DSUPPORT_DYN_ART
c-flags += -DCC_DRIVER=1 -Wall -Wextra -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -O2

# Libraries
LIBS :=  teeagentcommon${TARG}

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon/src/
c-flags += -I$(TOPDIR)/libs/libart/include
c-flags += -I$(TOPDIR)/libs/libmspcore/include
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/eSE/hisee
c-flags += -I$(PLATFORM_DIR)/common/tee_config
c-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config

include $(TOPDIR)/mk/ta-common.mk

ifeq ($(CONFIG_DYNLINK),y)
TA_LDFLAGS += -e tee_task_entry
endif
