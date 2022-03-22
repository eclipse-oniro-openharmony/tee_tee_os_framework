# ccdriver_lib
inc-flags += -I$(SOURCE_DIR)/platform/mtk/ccdriver_lib/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/crys/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/sym/driver/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/host/src/cc710teelib/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/rsa/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/utils/src/common/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/rnd_dma/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/pki/pka/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/common/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/sym/api/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/fips/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/proj/cc710tee/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/codesafe/src/crys/ecc/ecc_domains/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/pal/
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/mtk/tzcc_fw/shared/include/pal/hmos/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/kernel
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/mtk
CFILES += platform/common/cc_driver/mtk/cc_driver_adapt.c
CFILES += platform/mtk/ccdriver_lib/mtk_adapt.c
CFILES += platform/common/cc_driver/cc_driver_hal.c
CFILES += platform/mtk/ccdriver_lib/cc_driver_syscall.c

# secboot
CFILES += platform/mtk/secboot/secureboot.c

# for oemkey
inc-flags += -I$(SOURCE_DIR)/platform/common/plat_cap
CFILES += platform/common/plat_cap/plat_cap_hal.c

# spi
inc-flags += -I$(SOURCE_DIR)/platform/mtk/spi/inc
CFILES += platform/mtk/spi/spi_mtk.c

# fignerprint
CFILES += platform/mtk/fingerprint/src/tee_fingerprint.c

# gpio
inc-flags += -I$(SOURCE_DIR)/platform/mtk/gpio/inc
CFILES += platform/mtk/gpio/gpio_mtk.c

#gatekeeper syscall
include $(SOURCE_DIR)/platform/common/gatekeeper/gatekeeper_drv.mk
