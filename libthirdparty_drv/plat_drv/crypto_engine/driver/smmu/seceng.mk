#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_driver.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
	-I$(MODULE_DIR)/../../include \
	-I$(HI_PLAT_ROOT_DIR)/main \
	-I$(MODULE_DIR)/../../../secmem/include

MODULE_COBJS-y := \
	$(call module-dir-cobjs)

#########################################################
# module make
#########################################################
$(eval $(call module-make))
