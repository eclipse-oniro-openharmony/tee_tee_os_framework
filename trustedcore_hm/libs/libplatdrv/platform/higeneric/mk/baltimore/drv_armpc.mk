# baltimore
# hisi common includes
ifeq ($(chip_type), es)
inc-flags += -I$(SOURCE_DIR)/../../../../../../vendor/hisi/ap/platform/baltimore_es
else
inc-flags += -I$(SOURCE_DIR)/../../../../../../vendor/hisi/ap/platform/baltimore
endif
inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include

ifeq ($(chip_type), es)
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/baltimore_es
else
inc-flags += -I$(SOURCE_DIR)/platform/kirin/include/platform/baltimore
endif

#NPU //baltimore enable compile
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/uapi
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/inc
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/device
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/manager
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/platform

#for list.h interface
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v200/platform/hi36a0
inc-flags += -I$(AP_PLAT_HEAD_PATH)
#inc-flags += -I$(NPU_DRIVER_INC_PATH)
#inc-flags += -I$(NPU_INC_PATH)
$(warning AP_PLAT_HEAD_PATH $(AP_PLAT_HEAD_PATH))

# c++
USE_GNU_CXX = y
inc-flags += -I$(TOPDIR)/thirdparty/opensource/libbz_hm/src
LIBS += bz_hm

# tzarch
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tzarch/include

#
# Software workaround for baltimore SoC WE func.
# When SoC support WE and L3 exlusive, we may need it
#
inc-flags += -DCONFIG_SOC_WE_WORKAROUND

# secureboot
inc-flags += -DWITH_IMAGE_LOAD_SUPPORT \
	    -DCONFIG_DYNAMIC_MMAP_ADDR
inc-flags += -DCONFIG_CHECK_PTN_NAME
inc-flags += -DCONFIG_CHECK_PLATFORM_INFO


inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/include \
	    -I$(SOURCE_DIR)/platform/common/include/ivp

# use for baltimore and later platform
inc-flags += -DCONFIG_HISI_SECBOOT_IMG_V2
ifeq ($(WITH_ENG_VERSION), true)
inc-flags += -DCONFIG_HISI_SECBOOT_DEBUG
endif

#CFILES += platform/kirin/secureboot/secureboot_v2.c \
#	  platform/kirin/secureboot/secboot.c \
#	  platform/kirin/secureboot/process_hifi_info.c

inc-flags += -DCONFIG_HISI_NVIM_SEC
inc-flags += -DCONFIG_HISI_IVP_SEC_IMAGE

inc-flags += -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/ \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/include \
	    -I$(SOURCE_DIR)/platform/kirin/secureboot/bspatch/include/bsdiff

ifeq ($(CONFIG_DX_ENABLE), true)
# ccdriver_lib
inc-flags += -I$(SOURCE_DIR)/platform/kirin/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc712
CFILES += platform/common/cc_driver/cc712/cc_driver_adapt.c \
		  platform/kirin/ccdriver_lib/cc_adapt.c \
		  platform/kirin/ccdriver_lib/cc_power.c \
		  platform/common/cc_driver/cc_driver_hal.c

endif

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey/derive_teekey_armpc.mk

inc-flags += -DCONFIG_DSS_TYPE_BALTIMORE

# touchscheen
inc-flags += -I$(SOURCE_DIR)/platform/common/touchscreen		\
	    -I$(SOURCE_DIR)/platform/common/touchscreen/panel	\
	    -I$(SOURCE_DIR)/platform/kirin/touchscreen \
		-I$(SOURCE_DIR)/platform/common/tui

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/teeapi
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/sdk/gpapi
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src

# teeos shared memmory
CFILES += platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem
