#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libmspe_power_hook.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += $(call hi-include-dir-add, \
    $(MODULE_DIR) \
)

MODULE_COBJS-y :=

MODULE_COBJS-$(CONFIG_HISI_MSPE_POWER_SCHEME) += mspe_power_hook.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
