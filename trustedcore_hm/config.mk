arch_list := arm aarch64

ifeq ($(PLATFORM_NAME), )
ifeq ($(PRODUCT_NAME), )
export TARGET_BOARD_PLATFORM ?= kirin990
endif
endif

# for bootfs size
HM_BOOTFS_SIZE ?= "8000K"

# hmos release version
export HM_SDK_VER := hm-teeos-release

