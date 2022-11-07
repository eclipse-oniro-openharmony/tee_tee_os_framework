export PLAT_AUTOCONF_FILE := $(PREBUILD_DIR)/headers/platautoconf.h

DEBUG_RELEASE_MACRO := release
ifeq ($(PLAT_CONFIG_DEBUG), true)
DEBUG_RELEASE_MACRO := debug
endif

export CONFIG_FILE := $(TOPDIR)/config/$(DEBUG_RELEASE_MACRO)_config/$(TARGET_BOARD_PLATFORM)_$(DEBUG_RELEASE_MACRO)_config
