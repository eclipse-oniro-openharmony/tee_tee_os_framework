inc-flags += -I$(SOURCE_DIR)/platform/libthirdparty_drv/plat_drv/ccdriver_lib/include
inc-flags += -I$(SOURCE_DIR)/platform/common/crypto
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/codesafe/src/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
CFILES += platform/libthirdparty_drv/plat_drv/ccdriver_lib/cc_power.c \
          platform/libthirdparty_drv/plat_drv/ccdriver_lib/cc_adapt.c
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc712
CFILES += platform/common/cc_driver/cc712/cc_driver_adapt.c \
          platform/common/cc_driver/cc_driver_hal.c

ifneq ($(product_type), armpc)
inc-flags += -DCONFIG_USE_DUAL_ENGINE
CFILES += platform/libthirdparty_drv/plat_drv/ccdriver_lib/eps_adapt.c \
          platform/libthirdparty_drv/plat_drv/ccdriver_lib/eps_driver_hal.c
endif
