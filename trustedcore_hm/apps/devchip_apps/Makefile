HI_TEE_API_DIR := $(TOPDIR)/vendor/huanglong/libdevchip_api
HI_TEE_TA_DIR := $(TOPDIR)/vendor/huanglong/devchip_apps

all:$(devchip_apps)
$(devchip_apps):
	@ make -C $(HI_TEE_TA_DIR)/$@ ARCH=arm TARG=_a32 -f $(TOPDIR)/prebuild/hm-teeos-local-release/headers/.config -f Makefile HI_TEE_API_DIR=$(HI_TEE_API_DIR) HI_TEE_TA_DIR=$(HI_TEE_TA_DIR) all
