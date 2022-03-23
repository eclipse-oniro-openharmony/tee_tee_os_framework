#########################################################
# module initialize
# init MODULE_DIR / MODULE_INCLUDES to default
# $(call module-init, library_name.a, [y/n, default is y])
# MODULE_LIB-y
#########################################################
$(eval $(call module-init, libcustom_cdrm_video.a, y))

#########################################################
# module configure
#########################################################
MODULE_INCLUDES += \
		   -I$(MODULE_DIR)/../../../../../../../../../../hisi/confidential/hieps/crypto/hisee_seceng/libseceng/hieps/hal/include \
		   -I$(MODULE_DIR)/../../../../../../../libs/libchinadrm/include \
		   -I$(MODULE_DIR)/../../../../../../../thirdparty/huawei/libhwsecurec/include/libhwsecurec/ \
		   -I$(MODULE_DIR)/../../../../../../../sys_libs/libteeconfig/include \
		   -I$(MODULE_DIR)/../../../../../../../sys_libs/libhmdrv_stub/include \
		   -I$(MODULE_DIR)/../../../../../../../sys_libs/libtimer_a32/include

MODULE_COBJS-y := \
	hisee_video_ops.o \
	hisee_video.o \
	hisee_video_syscall_handle.o

#########################################################
# module make
#########################################################
$(eval $(call module-make))
