# napa
inc-flags += -I$(SOURCE_DIR)/../../../../../../../vendor/hisi/ap/platform/napa
inc-flags += -I$(SOURCE_DIR)/platform \
             -I$(SOURCE_DIR)/platform/common/include \
             -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/ccdriver_lib \
             -I$(SOURCE_DIR)/platform/libthirdparty_drv/include
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secureboot/bspatch \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/isp \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/hifi \
             -I$(TOPDIR)/libs/libplatdrv/platform/libthirdparty_drv/plat_drv/secmem/include \
             -I$(TOPDIR)/libs/libplatdrv/platform/common/include/ivp

# hisi common includes
inc-flags += -I$(SOURCE_DIR)/platform \
             -I$(SOURCE_DIR)/platform/common/include

# deleted when eps fit
CFILES += $(TOPDIR)/libs/libplatdrv/platform/common/soft_rand.c

# oemkey
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/oemkey/oemkey_driver.mk
include $(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/derive_teekey/derive_teekey_stub.mk

# secmem_ddr
CFILES += platform/libthirdparty_drv/plat_drv/secmem/driver/sec/ddr_sec_dummy_api.c

c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/include
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/inner_sdk/teeapi
c-flags += -I$(TOPDIR)/prebuild/hm-teeos-release/headers/sdk/gpapi
c-flags += -I$(TOPDIR)/sys_libs/libteeagentcommon_client/src
