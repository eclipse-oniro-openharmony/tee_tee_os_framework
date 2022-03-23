#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libmspe_crypto_selftest.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += $(call hi-include-dir-add, \
    $(HI_SECENG_DIR)/$(HI_PROJECT)/hal/include \
    $(MODULE_DIR) \
)

MODULE_COBJS-y := mspe_crypto_selftest.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
