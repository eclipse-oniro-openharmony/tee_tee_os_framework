#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_adapter.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
	-I$(MODULE_DIR)/../../../common/crypto \
	-I$(MODULE_DIR)/include

MODULE_COBJS-y := \
	$(call module-dir-cobjs)

#########################################################
# module make
#########################################################
$(eval $(call module-make))
