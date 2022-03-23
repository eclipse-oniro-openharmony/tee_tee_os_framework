#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_driver.a, y))

#########################################################
# module configure
#########################################################
 MODULE_INCLUDES += $(call hi-include-dir-add, \
    $(HI_SOC_INC) \
    $(HI_SECENG_DIR)/$(HI_PROJECT)/hal/include \
    $(call hi-chip-dir,$(MODULE_DIR)/chip) \
)

MODULE_COBJS-y := \
    $(call module-dir-cobjs) \
    $(call module-chip-cobjs)

#########################################################
# module make
#########################################################
$(eval $(call module-make))
