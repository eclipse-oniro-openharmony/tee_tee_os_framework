
LOCAL_PATH := $(call my-dir)
#CLEAR_VARS := $(LOCAL_PATH)/clear.mk
TRUSTEDCORE_MK := $(call my-dir)
SECURE_OS_DIR := $(LOCAL_PATH)/../../../..
ARCH := arm
include $(CLEAR_VARS)

# picked from trustedcore_plats.mk in rtosck project
WITH_CHIP_HI3650 := 0
WITH_CHIP_HI3660 := 2   # mate 9
WITH_CHIP_HI3670 := 3   # mate 10 / kirin970
WITH_CHIP_HI3680 := 4   # kirin980
WITH_CHIP_HI6260 := 5   # ?? miami
WITH_CHIP_KIRIN990 := 6   # phoenix
WITH_CHIP_ORLANDO := 7   # orlando
WITH_CHIP_HI6250 := 8   # dallas
WITH_CHIP_MT6765 := 9   # MTK
WITH_CHIP_BALTIMORE := 10   # baltimore
WITH_CHIP_DENVER := 11   # denver
WITH_CHIP_MIAMICW := 12   # miamicw
WITH_CHIP_LAGUNA := 13   # laguna

## for packaging variables:
ifneq ($(findstring hi3660, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_HI3660
endif

ifneq ($(findstring kirin970, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_HI3670
endif
ifneq ($(findstring kirin980, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_HI3680
endif

ifneq ($(findstring baltimore, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_BALTIMORE
endif

ifneq ($(findstring denver, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_DENVER
endif

ifneq ($(findstring laguna, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_LAGUNA
endif

ifneq ($(findstring miamicw, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_MIAMICW
endif

ifneq ($(findstring kirin710, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_HI6260
endif

ifneq ($(findstring kirin990, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_KIRIN990
endif

ifneq ($(findstring orlando, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_ORLANDO
endif

ifneq ($(findstring hi6250, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_HI6250
endif

ifneq ($(findstring mt6765, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_MT6765
endif

ifneq ($(findstring mt6761, $(TARGET_BOARD_PLATFORM)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_MT6765
endif

ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), )
TRUSTEDCORE_CHIP_CHOOSE := WITH_CHIP_HI3670
endif

LOCAL_CFLAGS += $(gcc-plugin-c-flags)
# all target flags for both c & c++ compiler

LPAE_SUPPORT := true

LOCAL_CFLAGS += -DTEE_SUPPORT_HIVCODEC

ifeq (, $(filter $(TARGET_BOARD_PLATFORM), hi3660))
LOCAL_CFLAGS += -DTEE_SUPPORT_TZMP2
endif

## add eng config
ifeq ($(TARGET_BUILD_VARIANT),eng)
LOCAL_CFLAGS += -DVCODEC_ENG_VERSION
else
LOCAL_CFLAGS := $(filter-out -DVCODEC_ENG_VERSION,$(flags))
endif

ifneq ($(filter 4.6 4.6.%, $(TARGET_GCC_VERSION)),)
TRUSTEDCORE_ASFLAG_SET := false
else
TRUSTEDCORE_ASFLAG_SET := true
endif
TRUSTEDCORE_ARCH_CHOOSE := ARM
TRUSTEDCORE_BUILD_RAW_STATIC_LIBRARY = $(LOCAL_PATH)/trustedcore_static_library_build.mk

# include $(LOCAL_PATH)/trustedcore_cfg.mk
# LOCAL_CFLAGS += flags

LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/libc_32/arch/generic/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/libc/hm/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/sdk/gpapi/common/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/sys/hmapi/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/ddk/hmapi/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/ddk/legacy/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../drivers/platdrv/include/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../drivers/include/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/inner_sdk/legacy/uapi/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../sys_libs/libteeconfig/include/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../sys_libs/libteeconfig/include/kernel/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/libhwsecurec/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../sys_libs/libtimer/inc/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/inner_sdk/teeapi/common/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/inner_sdk/hmapi/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/inner_sdk/legacy/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/libc/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/libc/arch/aarch64/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../sys_libs/libteeconfig/include/TEE_ext/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../sys_libs/libteeconfig/include/kernel/
LOCAL_CFLAGS += -I$(SECURE_OS_DIR)/../../../hmos-ddk/code/include/hmos/libc/

ifeq ($(HM_OPEN), true)
LOCAL_CFLAGS += -DENABLE_DRM_HM
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_HI3670)
PRODUCT_DIR  := HiVCodecV200
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/kirin970
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_HI3680)
PRODUCT_DIR  := HiVCodecV200
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/kirin980
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_KIRIN990)
PRODUCT_DIR  := HiVCodecV500
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/kirin990
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_ORLANDO)
PRODUCT_DIR  := HiVCodecV200
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/orlando
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_HI6260)
PRODUCT_DIR  := HiVCodecV200
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/kirin710
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_DENVER)
PRODUCT_DIR  := HiVCodecV500
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/denver
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_LAGUNA)
PRODUCT_DIR  := HiVCodecV500
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/laguna
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_BALTIMORE)
PRODUCT_OUT_DIR :=  $(SECURE_OS_DIR)/../../../../../../out/target/product/baltimore
endif
################################################
## include path
################################################
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_BALTIMORE)
include $(LOCAL_PATH)/vdec_baltimore/vfmw/vfmw_v6.2/product/HiVCodecV600/sec_cfg/vfmw_make.cfg
VFMW_CFILES := $(VFMW_SRC)
VFMW_CFLAGS += -DVDH_BASE_PHY_ADDR=0xe9200000
else
include $(TOP)/vendor/hisi/ap/hardware/vcodec/hi_vcodec/hi_omx/omx_component/vdec_hivna/core/vfmw/vfmw_v4.0/firmware/product/$(PRODUCT_DIR)/SEC_CFG/vfmw_make.cfg
endif

LOCAL_C_INCLUDES  := $(INCLUDE)
LOCAL_CFLAGS += -DTEE_SUPPORT_HIVCODEC
LOCAL_SRC_FILES   := $(VFMW_CFILES)

LOCAL_CFLAGS      += $(VFMW_CFLAGS)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/hm/kernel
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/../../prebuild/hm-teeos-release/headers/kernel/uapi
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_HI3670)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/kirin970
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_HI3680)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/kirin980
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_KIRIN990)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/kirin990
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_DENVER)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/denver
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_LAGUNA)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/laguna
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_ORLANDO)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/orlando
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_HI6260)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/kirin710
endif
ifeq ($(strip $(TRUSTEDCORE_CHIP_CHOOSE)), WITH_CHIP_BALTIMORE)
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/include
LOCAL_CFLAGS      += -I$(SECURE_OS_DIR)/platform/kirin/secmem/driver/iommu
LOCAL_CFLAGS      += -I$(TOP)/vendor/hisi/ap/platform/baltimore
endif
LOCAL_CFLAGS      += -O2 -fPIC
LOCAL_CFLAGS      += -march=armv8-a
ifeq ($(strip $(TRUSTEDCORE_ASFLAG_SET)), true)
LOCAL_ASFLAGS     += -march=armv8-a -fpie
endif

ifeq ($(CFG_CONFIG_HISI_FAMA),true)
LOCAL_CFLAGS += -DCONFIG_HISI_FAMA
endif
LOCAL_MODULE      := libsec_decoder
LOCAL_MODULE_PATH := $(PRODUCT_OUT_DIR)
LOCAL_MODULE_TAGS := optional

$(shell rm $(LOCAL_PATH)/$(LOCAL_MODULE).a)
$(shell rm ${PRODUCT_OUT_DIR}/obj/STATIC_LIBRARIES/$(LOCAL_MODULE)_intermediates/$(LOCAL_MODULE).a)

include $(TRUSTEDCORE_BUILD_RAW_STATIC_LIBRARY)
