#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_osa_plat.a, y))

#########################################################
# module configure
#########################################################
$(eval $(call module-cflags-addsuffix, $(INCLUDES)))
MODULE_COBJS-y := \
	$(call module-dir-cobjs,$(HI_OS_TYPE))

#########################################################
# module make
#########################################################
$(eval $(call module-make))
