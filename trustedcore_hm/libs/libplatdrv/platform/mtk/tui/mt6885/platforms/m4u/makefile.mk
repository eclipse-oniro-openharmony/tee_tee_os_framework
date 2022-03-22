
LOCAL_GENERIC_PATH = Locals/Code/platforms/generic
LOCAL_M4U_PATH = Locals/Code/platforms/m4u
LOCAL_CMDQ_PATH = Locals/Code/platforms/cmdq

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE:=tui_m4u_includes
LOCAL_EXPORT_C_INCLUDE_DIRS += \
	${LOCAL_CMDQ_PATH}/ \
	${LOCAL_M4U_PATH}/ \
	${LOCAL_GENERIC_PATH}/ \
	vendor/mediatek/proprietary/bootable/bootloader/preloader/platform/$(MTK_PLATFORM_DIR)/src/core/inc \
	vendor/mediatek/proprietary/bootable/bootloader/preloader/platform/$(MTK_PLATFORM_DIR)/src/security/trustzone/inc

include $(BUILD_HEADER_LIBRARY)
LOCAL_HEADER_LIBRARIES += tui_m4u_includes

SRC_C += ${LOCAL_M4U_PATH}/tui_m4u.c
