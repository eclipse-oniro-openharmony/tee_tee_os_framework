#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_pal.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
    -I$(PROJECT_ROOT_DIR)/drivers/platdrv/include/ \
    -I$(call hi-chip-dir,$(HI_PLAT_ROOT_DIR)/driver/power/chip) \
    -I$(MODULE_DIR)/../../../secmem/include \
    -I$(MODULE_DIR)/../../../../../../../prebuild/hm-teeos-release/headers/inner_sdk/legacy

MODULE_COBJS-y := \
    $(call module-dir-cobjs)

#########################################################
# module make
#########################################################
$(eval $(call module-make))
