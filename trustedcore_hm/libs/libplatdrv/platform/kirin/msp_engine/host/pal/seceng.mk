#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_pal.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
    -I$(PROJECT_ROOT_DIR)/drivers/platdrv/include/ \
    -I$(call hi-chip-dir,$(HI_PLAT_ROOT_DIR)/driver/power/chip) \
    -I$(MODULE_DIR)/../../../secmem/include \
    -I$(MODULE_DIR)/../../../../../../../prebuild/hm-teeos-release/headers/inner_sdk/legacy

MODULE_COBJS-y := \
    pal_cpu_plat.o \
    pal_exception_plat.o \
    pal_interrupt_plat.o \
    pal_log_plat.o \
    pal_mem_plat.o \
    pal_nv_cfg_plat.o \
    pal_timer_plat.o

MODULE_COBJS-$(CONFIG_HISI_MSPE_SMMUV2) += pal_smmuv2_plat.o
MODULE_COBJS-$(CONFIG_HISI_MSPE_SMMUV3) += pal_smmuv3_plat.o


#########################################################
# module make
#########################################################
$(eval $(call module-make))
