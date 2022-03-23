#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_pal_plat_dft.a, y))

#########################################################
# module configure
#########################################################
$(eval $(call module-cflags-addsuffix, $(INCLUDES)))
MODULE_INCLUDES +=-I$(MODULE_DIR)/../../../../../../../drivers/platdrv/include/

MODULE_COBJS-y := \
	$(call module-dir-dftobjs)

#########################################################
# module make
#########################################################
$(eval $(call module-make))
