#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libmspe_smmu.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
	-I$(MODULE_DIR)/../../include \
	-I$(HI_PLAT_ROOT_DIR)/main \
	-I$(MODULE_DIR)/../../../secmem/include

MODULE_COBJS-y :=

MODULE_COBJS-$(CONFIG_HISI_MSPE_SMMUV2) += mspe_smmu_v2.o
MODULE_COBJS-$(CONFIG_HISI_MSPE_SMMUV3) += mspe_smmu_v3.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
