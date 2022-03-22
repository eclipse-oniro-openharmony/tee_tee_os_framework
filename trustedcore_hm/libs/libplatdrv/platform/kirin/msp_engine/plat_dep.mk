#########################################################
# params init
#########################################################
PROJECT_ROOT_DIR      ?= $(HI_PLAT_ROOT_DIR)/../../../../..
PROJECT_ROOT_DIR      := $(abspath $(PROJECT_ROOT_DIR))
ARCH                  ?= arm
PRODUCT_NAME          ?= phone
chip_type             ?= $(HI_CHIP_TYPE)
OBB_PRODUCT_NAME      ?= $(HI_CHIP_NAME)
TARGET_BOARD_PLATFORM ?= $(HI_CHIP_NAME)
TARGET_BUILD_VARIANT  ?= $(if $(filter $(HI_DFT_ENABLE),true),eng,user)
TOPDIR                ?= $(PROJECT_ROOT_DIR)
TOP                   ?= $(ANDROID_TOP_ABS_DIR)
OUTPUTDIR             ?= $(PROJECT_ROOT_DIR)/output
PLATFORM_DIR          ?= $(PROJECT_ROOT_DIR)/platform
AP_PLAT_HEAD_PATH     ?= $(HI_AP_PLATFORM_DIR)

# output dir
ifneq ($(BUILD_DIR),)
    HI_OUT_DIR := $(abspath $(BUILD_DIR))/platdrv/msp_engine
endif

#########################################################
# compiler
#########################################################
ifeq ($(HI_PC_UT),true)
    include $(PC_UT_WORK_DIR)/plat_dep.mk
    include $(TOPDIR)/mk/plat.mk
    include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/product_config.mk
else
    ifeq ($(HM_TOOLCHAIN)$(HI_STATIC_CHECK),true)
        include $(TOPDIR)/prebuild/hm-teeos-release/headers/.config
        include $(TOPDIR)/config.mk
        include $(TOPDIR)/drivers/platdrv/Makefile
    endif
endif

#########################################################
# compiler & options
#########################################################
PROJECT_HDR_DIR := $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers
PROJECT_SYS_INC := $(PROJECT_ROOT_DIR)/sys_libs/libteeconfig/include
HI_PLAT_DEP_INCLUDES += $(call hi-include-dir-add,\
    $(HI_PLAT_ROOT_DIR)/custom/include \
    $(PROJECT_HDR_DIR)/hm_32 \
    $(PROJECT_HDR_DIR)/kernel/uapi \
    $(PROJECT_HDR_DIR)/kernel/kirin \
    $(PROJECT_HDR_DIR)/kernel/arch/$(ARCH)/uapi \
    $(PROJECT_HDR_DIR)/kernel/arch/$(ARCH) \
    $(PROJECT_SYS_INC)/kernel \
    $(PROJECT_SYS_INC)/TEE_ext \
)

ifeq ($(HI_PC_UT),true)
    # pc ut config
    HI_PLAT_DEP_CFLAGS += -D__arm_ -DThreadUpdateCA=0 -Dhmobj_SPcanary=0 -DSPcanaryUpdate=0 -DTeecallRegister_Notify_Mem=0 -DTeecallSpi_Notify_Shadow=0 -DTeecallSpi_Notify_Wakeup=0 -DTeecallHm_Task_Update_Ca=0 -Dasm=__asm__
    HI_PLAT_DEP_CFLAGS += $(call hi-include-dir-add,\
        $(PROJECT_HDR_DIR) \
        $(PROJECT_HDR_DIR)/libc_32/arch/$(ARCH) \
        $(PROJECT_ROOT_DIR)/sys_libs/libhmdrv_stub \
        $(PROJECT_ROOT_DIR)/sys_libs/libhmdrv_stub/include \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/sdk/teeapi/common \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/sdk/gpapi/common \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/inner_sdk/hm_32 \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/inner_sdk/legacy \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/inner_sdk/legacy/uapi \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/inner_sdk/teeapi/common \
        $(PROJECT_ROOT_DIR)/sys_libs/libteeconfig/include \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/ddk/legacy \
        $(PROJECT_ROOT_DIR)/drivers/platdrv/include \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/ddk/hmapi \
        $(PROJECT_ROOT_DIR)/sys_libs/libtimer/inc \
        $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/inner_sdk/hmapi \
        $(PROJECT_ROOT_DIR)/drivers/include \
        $(PROJECT_ROOT_DIR)/libs/libplatdrv/platform/kirin/ccdriver_lib/include \
        $(PROJECT_ROOT_DIR)/libs/libplatdrv/platform/kirin/secmem/include \
        $(PROJECT_ROOT_DIR)/libs/libplatdrv/platform/kirin/msp_ta_channel/ \
    )
    HI_PLAT_DEP_CFLAGS += $(HI_PLAT_DEP_INCLUDES)
    HI_PLAT_DEP_CXXFLAGS += $(call hi-include-dir-add, \
        $(HI_PLAT_ROOT_DIR)/custom/include \
    )
    HI_PLAT_DEP_INCLUDES :=
else
    # teeos compile config
    ifeq ($(GCC_TOOLCHAIN),)
        include $(PROJECT_ROOT_DIR)/config.mk
        include $(PROJECT_ROOT_DIR)/mk/toolchain.mk
    endif

    HI_PLAT_DEP_ARFLAGS := -rcs
    # $(error HI_PLAT_DEP_CFLAGS = $(filter-out -D% -I% -include%, $(inc-flags) $(c-flags)))
    HI_PLAT_DEP_CFLAGS := --gcc-toolchain=$(GCC_TOOLCHAIN) --sysroot=$(SYSROOT) --target=$(TARGET_ARCH) -flto -fsplit-lto-unit -fvisibility=default -fsanitize=cfi -fno-sanitize=cfi-icall -fPIC -fdata-sections -ffunction-sections -fstack-protector-strong -nodefaultlibs -Oz -Wall -Wextra -fno-omit-frame-pointer -fno-short-enums -munaligned-access -fmax-type-align=1 -fno-builtin -Wno-implicit-fallthrough
    HI_PLAT_DEP_CFLAGS += $(call hi-include-dir-add,\
        $(PROJECT_HDR_DIR)/libc_32 \
        $(PROJECT_HDR_DIR)/libc_32/arch/$(ARCH) \
        $(PROJECT_HDR_DIR)/libc_32/arch/generic \
    )

    # static check
    ifeq ($(HI_STATIC_CHECK),true)
        HI_PLAT_DEP_CFLAGS += $(inc-flags)
        HI_PLAT_DEP_CFLAGS += $(c-flags)
        HI_PLAT_DEP_CFLAGS += $(flags) -Wno-unused-parameter
    endif

    # pclint
    ifeq ($(HI_PC_LINT), true)
        # clear warn in stdlib.h hmapi.h
        HI_PLAT_DEP_CFLAGS += -D_Noreturn -D__arm__
    endif
endif
