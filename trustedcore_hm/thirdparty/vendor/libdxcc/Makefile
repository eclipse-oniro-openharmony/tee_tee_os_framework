# MODULE is a lib
ifeq ($(filter $(TARGET_BOARD_PLATFORM), kirin980 kirin990 orlando baltimore burbank lexington denver laguna hi9500 hi9510), )
MODULE := libdx_cc7_a32.a
else
MODULE := libdx_cc7.a
endif

override SOURCE_DIR:=$(TOPDIR)/thirdparty/vendor/libdxcc
override DX_SOURCE_DIR:=$(TOPDIR)/thirdparty/vendor/
inc-flags += -I$(TOPDIR)/tools/
inc-flags += -I$(PREBUILD_HEADER)/boringssl
# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(SOURCE_DIR)/austin/host/src/cclib/dx_cclib.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/host/include/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/crys/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/dx_util/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/pal/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/codesafe/src/crys/rsa/crys_rsa/inc/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/sep_ctx.h)

EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/pal/include/*.h)
include $(TOPDIR)/mk/var.mk
ifneq ($(filter $(TARGET_BOARD_PLATFORM), kirin970 kirin710 miamicw qemu hi6965 hi6932), )
# Source files required to build the target
include $(DX_SOURCE_DIR)/libdxcc/austin.mk
include $(TOPDIR)/mk/lib-common.mk

# The following is ugly, before we do header files cleanup, we dont put nostdinc
# in the build system for the purpose of using system libc headers as a backup
# However we dont have ctypes.h for bootstrap header file system, so we filter nostdinc
# as a temperary solution
flags := $(filter-out -nostdinc,$(flags))
c-flags := $(filter-out -nostdinc,$(c-flags))
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), shaolingun, hi3716mv430n), )
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/host/src/cc7x_teelib/cc_lib.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/pal/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/pal/hmos/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/crypto_api/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/crypto_api/cc7x_tee/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/proj/cc7x_tee/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/cc_util/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/host/src/cclib/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/host/src/cclib/dx_cclib.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/host/include/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/crys/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/dx_util/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/pal/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/codesafe/src/crys/rsa/crys_rsa/inc/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/austin/shared/include/sep_ctx.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/pal/include/*.h)
all:install_headers
endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), kirin980 orlando kirin990 hi9500 hi9510 denver baltimore burbank lexington laguna), )
## TODO: this is very ugly. need rework!!!!!!!
##       But we need to checkin code today.

EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/host/src/cc7x_teelib/cc_lib.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/pal/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/pal/hmos/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/crypto_api/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/crypto_api/cc7x_tee/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/proj/cc7x_tee/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/atlanta/shared/include/cc_util/*.h)
INSTALL_FILE_a32 = $(LIB_DIR)/libdx_cc7_a32.a
INSTALL_FILE = $(OUTPUTDIR)/aarch64/libs/$(MODULE)
MODULE_FILE  := $(BUILD_DIR)/$(MODULE)
all: $(INSTALL_FILE)
$(INSTALL_FILE):
	@ echo $(HDR_L_DIR)
	@ PATH="$(GCC_TOOLCHAIN_A32)/bin:$(PATH)" PREBUILD_HEADER=$(PREBUILD_HEADER) HDR_L_DIR=$(HDR_L_DIR) TARG=_a32 $(MAKE) -C $(DX_SOURCE_DIR)/libdxcc/atlanta clean
	@ PATH="$(GCC_TOOLCHAIN_A32)/bin:$(PATH)" PREBUILD_HEADER=$(PREBUILD_HEADER) HDR_L_DIR=$(HDR_L_DIR) TARG=_a32 $(MAKE) -C $(DX_SOURCE_DIR)/libdxcc/atlanta
	@ mkdir -p $(LIB_DIR)
	@ cp $(DX_SOURCE_DIR)/libdxcc/atlanta/host/lib/libcc_715tee.a $(INSTALL_FILE_a32)
	@ rm -rf $(DX_SOURCE_DIR)/libdxcc/atlanta/host/src/cc7x_teelib/build-arm-eabi/
	@ PATH="$(GCC_TOOLCHAIN_A64)/bin:$(PATH)" PREBUILD_HEADER=$(PREBUILD_HEADER) HDR_L_DIR=$(HDR_L_DIR) $(MAKE) -C $(DX_SOURCE_DIR)/libdxcc/atlanta clean
	@ PATH="$(GCC_TOOLCHAIN_A64)/bin:$(PATH)" PREBUILD_HEADER=$(PREBUILD_HEADER) HDR_L_DIR=$(HDR_L_DIR) $(MAKE) -C $(DX_SOURCE_DIR)/libdxcc/atlanta
	@ mkdir -p $(LIB_DIR)
	@ cp $(DX_SOURCE_DIR)/libdxcc/atlanta/host/lib/libcc_715tee.a $(INSTALL_FILE)
	@ rm -rf $(DX_SOURCE_DIR)/libdxcc/atlanta/host/src/cc7x_teelib/build-aarch64-linux-gnu/

endif

ifneq ($(filter $(TARGET_BOARD_PLATFORM), mt6765 mt6873 mt6853 mt6761 mt6768 mt6885), )

EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/mtk/tzcc_fw/host/src/cc710teelib/sns_silib.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/mtk/tzcc_fw/shared/include/pal/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/mtk/tzcc_fw/shared/include/pal/hmos/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/mtk/tzcc_fw/shared/include/crys/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/mtk/tzcc_fw/shared/include/crys/cc710tee/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/mtk/tzcc_fw/shared/include/proj/cc710tee/*.h)
EXPORT_HDRS += $(wildcard $(SOURCE_DIR)/mtk/tzcc_fw/shared/include/ssi_util/*.h)

INSTALL_FILE = $(LIB_DIR)/libdx_cc7_a32.a
MODULE_FILE  := $(BUILD_DIR)/$(MODULE)
all: $(INSTALL_FILE)
$(INSTALL_FILE):
	@ echo $(HDR_L_DIR)
	@ PATH="$(GCC_TOOLCHAIN_A32)/bin:$(PATH)" PREBUILD_HEADER=$(PREBUILD_HEADER) HDR_L_DIR=$(HDR_L_DIR) TARG=_a32 $(MAKE) -C $(DX_SOURCE_DIR)/libdxcc/mtk clean
	@ PATH="$(GCC_TOOLCHAIN_A32)/bin:$(PATH)" PREBUILD_HEADER=$(PREBUILD_HEADER) HDR_L_DIR=$(HDR_L_DIR) TARG=_a32 $(MAKE) -C $(DX_SOURCE_DIR)/libdxcc/mtk
	@ mkdir -p $(LIB_DIR)
	@ cp $(DX_SOURCE_DIR)/libdxcc/mtk/tzcc_fw/host/lib/libcc_710tee.a $(INSTALL_FILE)
	@ PATH="$(GCC_TOOLCHAIN_A32)/bin:$(PATH)" PREBUILD_HEADER=$(PREBUILD_HEADER) HDR_L_DIR=$(HDR_L_DIR) TARG=_a32 $(MAKE) -C $(DX_SOURCE_DIR)/libdxcc/mtk clean

endif


ifeq ($(filter $(TARGET_BOARD_PLATFORM),hi6965 hi6932 kirin970 kirin710 miamicw qemu), )
.PHONY: install_headers
install_headers:
	@ echo $(EXPORT_HDRS)
	@ echo $(HDR_INSTALL_DIR)
	@ cp -raf $(EXPORT_HDRS) $(HDR_INSTALL_DIR)/
endif
