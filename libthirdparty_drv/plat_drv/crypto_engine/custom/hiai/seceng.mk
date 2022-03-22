#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_custom_hiai.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += $(call hi-include-dir-add, \
    $(call hi-chip-dir,$(HI_PLAT_ROOT_DIR)/driver/power/chip) \
)

MODULE_COBJS-y := \
	$(call module-dir-cobjs)

#########################################################
# module make
#########################################################
$(eval $(call module-make))
