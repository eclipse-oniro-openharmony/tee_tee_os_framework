#dx
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/pal/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/host/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/host/src/cclib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/dx_util
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/austin/shared/include/crys
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/host/src/cc7x_teelib
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/pal/hmos
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/crypto_api/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/proj/cc7x_tee
inc-flags += -I$(TOPDIR)/thirdparty/vendor/libdxcc/atlanta/shared/include/cc_util
flags += -DDX_ENABLE=1

ifeq ($(CONFIG_TERMINAL_DRV_SUPPORT),y)
#cc_driver_syscall
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/cc63
inc-flags += -I$(SOURCE_DIR)/platform/common/cc_driver/huanglong

CFILES += platform/common/cc_driver/cc_driver_hal.c
CFILES += platform/common/cc_driver/cc63/cc_driver_adapt.c
CFILES += platform/common/cc_driver/huanglong/cc_driver_adapt.c
CFILES += platform/huanglong/ccdriver_lib/cc_driver_syscall.c

# oemkey
inc-flags += -I$(SOURCE_DIR)/platform/common/plat_cap
CFILES += platform/common/plat_cap/plat_cap_hal.c
CFILES += platform/huanglong/ccdriver_lib/keyservice.c

#dev_drv
define eval_drvs
drv_incs  :=
drv_srcs  :=
drv_flags :=

inc-flags += -I$$(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/$(1)
include $$(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/$(1)/itrustee.mk

$(1)_drv_incs  := $$(addprefix -I$$(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/$(1)/, $$(drv_incs))
$(1)_drv_srcs  := $$(addprefix ../../libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/$(1)/, $$(drv_srcs))
$(1)_drv_flags := $$(drv_flags)

inc-flags += $$($(1)_drv_incs)
inc-flags += $$($(1)_drv_flags)
CFILES    += $$($(1)_drv_srcs)
endef

include $(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/itrustee.mk
inc-flags += $(addprefix -I$(TOPDIR)/libs/libplatdrv/platform/huanglong/hi3751v900/devchip_drv/, $(drv_global_incdirs))
inc-flags += -I$(TOPDIR)/vendor/huanglong/libdevchip_api/include
inc-flags += -I$(TOPDIR)/vendor/huanglong/libdevchip_api/common
inc-flags += -I$(TOPDIR)/vendor/huanglong/libdevchip_api/npu/include
inc-flags += -I$(TOPDIR)/sys_libs/libtimer/include/sys_timer.h
inc-flags += -I$(PREBUILD_HEADER)/ddk/legacy \
              -I$(PREBUILD_HEADER)/inner_sdk/teeapi \
              -I$(PREBUILD_HEADER)/sdk/gpapi

$(foreach module, $(drv_dirs), $(eval $(call eval_drvs,$(module))))
endif
