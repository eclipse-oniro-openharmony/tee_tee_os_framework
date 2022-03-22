# hi9500
# # hisi common includes
# # ccdriver_lib
ifeq ($(CONFIG_DX_ENABLE), true)

inc-flags += -I$(SOURCE_DIR)/platform/balong/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
inc-flags += -I$(TOPDIR)/libs/libplatdrv/platform/
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc712
CFILES += platform/common/cc_driver/cc712/cc_driver_adapt.c
CFILES += platform/balong/ccdriver_lib/cc_adapt.c
CFILES += platform/common/cc_driver/cc_driver_hal.c
endif
