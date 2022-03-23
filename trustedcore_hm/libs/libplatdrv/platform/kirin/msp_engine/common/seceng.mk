#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_common.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
	-I$(MODULE_DIR)/../driver/agent/include \
	-I$(MODULE_DIR)/../main \
	-I$(call hi-chip-dir,$(MODULE_DIR)/../driver/power/chip)

MODULE_COBJS-y := hieps_common.o \
	hieps_smc.o

ifeq ($(HI_DFT_ENABLE),true)
MODULE_COBJS-y += mspe_test.o
MODULE_INCLUDES += \
    -I$(MODULE_DIR)/../../../../../../libs/libplatdrv/platform/kirin/msp_engine/autotest/custom/cdrm \
    -I$(MODULE_DIR)/../../../../../../libs/libplatdrv/platform/kirin/msp_ta_channel \
    -I$(MODULE_DIR)/../../../../../../sys_libs/libteeconfig/include \
    -I$(MODULE_DIR)/../../../../../../sys_libs/libtimer/include \
    -I$(MODULE_DIR)/../../../../../../sys_libs/libhmdrv_stub/include
endif

#########################################################
# module make
#########################################################
$(eval $(call module-make))
