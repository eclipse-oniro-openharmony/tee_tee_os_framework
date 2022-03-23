include $(TOPDIR)/mk/var.mk
PREBUILD_SDK  := $(PREBUILD_DIR)/headers/sdk
PREBUILD_INNER_SDK  := $(PREBUILD_DIR)/headers/inner_sdk
PREBUILD_DDK  := $(PREBUILD_DIR)/headers/ddk
PREBUILD_SYS  := $(PREBUILD_DIR)/headers/sys
PREBUILD_KERNEL := $(PREBUILD_DIR)/headers/kernel
SDK_INCLUDE_PATH_COMMON += $(PREBUILD_SDK)/teeapi/common \
                           $(PREBUILD_SDK)/gpapi/common

KERNEL_INCLUDE_PATH_COMMON = $(PREBUILD_KERNEL)/ \
                             $(PREBUILD_KERNEL)/uapi \
                             $(PREBUILD_KERNEL)/arch/arm/uapi

INNER_SDK_INCLUDE_PATH_COMMON += $(HDR_L_DIR) \
                                 $(PREBUILD_INNER_SDK)/teeapi/common \
                                 $(PREBUILD_INNER_SDK)/legacy/ \
                                 $(PREBUILD_INNER_SDK)/legacy/uapi \
                                 $(PREBUILD_INNER_SDK)/hmapi

DDK_INCLUDE_PATH_COMMON += $(PREBUILD_DDK)/hmapi/ \
                           $(PREBUILD_DDK)/legacy/uapi \
                           $(PREBUILD_DDK)/legacy/

SYS_INCLUDE_PATH += $(PREBUILD_SYS)/hmapi \
                    $(PREBUILD_SYS)/teeapi \
                    $(PREBUILD_SYS)/legacy \
                    $(PREBUILD_SYS)/legacy/uapi

ifeq ($(TARGET_IS_SYS),y)
INCLUDE_PATH += $(SYS_INCLUDE_PATH)
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(INNER_SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(PREBUILD_INNER_SDK)/teeapi/tui \
                $(PREBUILD_INNER_SDK)/teeapi \
                $(PREBUILD_SDK)/gpapi \
                $(PREBUILD_SDK)/teeapi

endif

ifeq ($(TARGET_IS_DRV),y)
INCLUDE_PATH += $(SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(INNER_SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(PREBUILD_DDK)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(PREBUILD_INNER_SDK)/teeapi
INCLUDE_PATH += $(PREBUILD_SDK)/gpapi
endif

ifeq ($(TARGET_IS_TA),y)
INCLUDE_PATH += $(SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(INNER_SDK_INCLUDE_PATH_COMMON)
INCLUDE_PATH += $(KERNEL_INCLUDE_PATH_COMMON)
INCLUDE_PATH +=	$(PREBUILD_INNER_SDK)/internal \
                 $(PREBUILD_INNER_SDK)/teeapi/tui \
                 $(PREBUILD_INNER_SDK)/teeapi  \
                 $(PREBUILD_INNER_SDK)/gpapi  \
                 $(PREBUILD_SDK)/teeapi \
                 $(PREBUILD_SDK)/gpapi
endif
