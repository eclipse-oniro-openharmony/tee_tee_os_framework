# lexington
inc-flags += -DTEMP_API_WITHOUT_ISP
inc-flags += -I$(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/lexington
CFILES += $(TOPDIR)/drivers/platdrv/src/temp_apis.c
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/kirin/secureboot/bspatch \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/hifi \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/isp \
             -I$(TOPDIR)/libs/libplatdrv/platform/kirin/secmem/include \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/ivp

#NPU
#for list.h interface
inc-flags += -I$(SOURCE_DIR)/platform/kirin/secmem/include
inc-flags += -I$(SOURCE_DIR)/platform/kirin/npu_v100/platform/hi6290

# c++
USE_GNU_CXX = y
inc-flags += -I$(TOPDIR)/thirdparty/opensource/libbz_hm/src
LIBS += bz_hm

# hisi_hwspinlock
CFILES += platform/kirin/seccfg/hisi_hwspinlock.c

# common includes
inc-flags += -I$(SOURCE_DIR)/platform \
	    -I$(SOURCE_DIR)/platform/common/include

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
		  platform/common/cc_driver/cc_driver_hal.c \
		  platform/kirin/ccdriver_lib/cc_adapt.c \
		  platform/kirin/ccdriver_lib/cc_power.c \
# eima2.0+rootscan
CFILES += platform/kirin/antiroot/nonsecure_hasher.c
endif

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/teeapi
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/sdk/gpapi
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src

# teeos shared memmory
CFILES += $(SOURCE_DIR)/platform/kirin/tee_sharedmem/bl2_sharedmem.c
inc-flags += -I$(SOURCE_DIR)/platform/kirin/tee_sharedmem

# libfdt
inc-flags += -I$(SOURCE_DIR)/platform/kirin/libfdt/include
CFILES += platform/kirin/libfdt/acpi.c \
		  platform/kirin/libfdt/fdt.c \
		  platform/kirin/libfdt/fdt_addresses.c \
		  platform/kirin/libfdt/fdt_empty_tree.c \
		  platform/kirin/libfdt/fdt_overlay.c \
		  platform/kirin/libfdt/fdt_ro.c \
		  platform/kirin/libfdt/fdt_rw.c \
		  platform/kirin/libfdt/fdt_strerror.c \
		  platform/kirin/libfdt/fdt_sw.c \
		  platform/kirin/libfdt/fdt_wip.c \
		  platform/kirin/libfdt/fdt_handler.c
