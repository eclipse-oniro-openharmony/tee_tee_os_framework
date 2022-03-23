#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
#########################################################
$(eval $(call module-init, libcrypto_custom_dft.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
	-I$(MODULE_DIR)/../driver/agent/include \
	-I$(MODULE_DIR)/../main \
	-I$(call hi-chip-dir,$(MODULE_DIR)/../driver/power/chip)

MODULE_COBJS-y += \
	hisee_video_cmaion_mgr.o \
	hisee_video_dft.o \
	hisee_video_perf.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
