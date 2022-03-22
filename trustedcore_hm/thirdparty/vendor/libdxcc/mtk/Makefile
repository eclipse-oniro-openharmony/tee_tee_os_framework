# "Root" Makefile for Host domain
# This makefile invokes the relevant target specific makefile to build it (e.g., cclib)
#

TARGET_IS_SYS := y
include $(TOPDIR)/mk/cfg.mk
INCDIRS_EXTRA:=	$(INCLUDE_PATH) \
    $(PREBUILD_HEADER)/ \
    $(PREBUILD_HEADER)/boringssl \
    $(PREBUILD_HEADER)/kernel/uapi \
    $(PREBUILD_HEADER)/kernel \
    $(PREBUILD_HEADER)/kernel/arch/arm/uapi \
    $(HDR_L_DIR) \
    $(PREBUILD_HEADER)/hm_32 \
    $(PREBUILD_HEADER)/libc_32 \
    $(PREBUILD_HEADER)/libc_32/arch/$(ARCH) \
    $(PREBUILD_HEADER)/libc_32/arch/generic \
    $(PREBUILD_HEADER)/gen/arch/$(ARCH) \
    $(TOPDIR)/drivers/platdrv/include

export INCDIRS_EXTRA

.PHONY: clean default
default:
	@$(if $(findstring _a32,${TARG}),$(MAKE) -C tzcc_fw/host/src/ ARCH=arm TARG=_a32 CROSS_COMPILE=arm-eabi-,$(MAKE) -C tzcc_fw/host/src/ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- )
	#@cp -rf tzcc_fw/host/lib/* lib/
clean:
	@$(if $(findstring _a32,${TARG}),$(MAKE) -C tzcc_fw/host/src/ ARCH=arm TARG=_a32 CROSS_COMPILE=arm-eabi- clean, $(MAKE) -C tzcc_fw/host/src/ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- clean)

# "Root" Makefile for Host domain
