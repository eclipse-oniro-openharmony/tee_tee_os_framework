#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libmspe_power.a, y))

#########################################################
# module configure
#########################################################
 MODULE_INCLUDES += $(call hi-include-dir-add, \
    $(HI_SOC_INC) \
    $(HI_SECENG_DIR)/$(HI_PROJECT)/hal/include \
    $(call hi-chip-dir,$(MODULE_DIR)/chip) \
    $(MODULE_DIR) \
)

MODULE_COBJS-y :=

# baltimore power use this
ifneq ($(CONFIG_HISI_MSPE_POWER_SCHEME),y)
	MODULE_COBJS-y += $(call module-chip-cobjs)
endif

MODULE_COBJS-$(CONFIG_HISI_MSPE_POWER_SCHEME) += \
	mspe_power.o \
	mspe_power_ctrl.o \
	mspe_power_dvfs.o \
	mspe_power_msg_route.o \
	mspe_power_mspe.o \
	mspe_power_state_mgr.o \
	mspe_power_compatible.o

MODULE_COBJS-$(CONFIG_HISI_MSPE_IN_MEDIA2) += \
	mspe_clk_volt/media2/mspe_power_clk_volt_plat.o \
	mspe_clk_volt/media2/mspe_power_mspe_plat.o


#########################################################
# module make
#########################################################
$(eval $(call module-make))
