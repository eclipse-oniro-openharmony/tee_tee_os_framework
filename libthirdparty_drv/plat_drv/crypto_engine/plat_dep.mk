#########################################################
# params init
#########################################################
PROJECT_ROOT_DIR ?= $(HI_PLAT_ROOT_DIR)/../../../../..
PROJECT_ROOT_DIR := $(call hi-dir-abs, $(PROJECT_ROOT_DIR))
TARGET_BUILD_VARIANT ?= $(if $(filter $(HI_DFT_ENABLE),true),eng,user)

# output dir
ifneq ($(BUILD_DIR),)
    HI_OUT_DIR := $(BUILD_DIR)platdrv/platform/kirin
endif
ifneq ($(SOURCE_DIR),)
    PROJ_PLAT_ROOT_DIR := $(SOURCE_DIR)/$(patsubst $(call hi-dir-abs, $(HI_PLAT_ROOT_DIR)/../../..)/%,%,$(HI_PLAT_ROOT_DIR))
endif

#########################################################
# compiler & options
#########################################################
HI_PLAT_DEP_INCLUDES += $(call hi-include-dir-add, \
    $(HI_PLAT_ROOT_DIR)/custom/include \
)

ifeq ($(HM_PLATFORM),)
    ARCH ?= arm
    PROJECT_HDR_DIR := $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers
    PROJECT_SYS_INC := $(PROJECT_ROOT_DIR)/sys_libs/libteeconfig/include
    HI_PLAT_DEP_INCLUDES += $(call hi-include-dir-add,\
        $(PROJECT_HDR_DIR)/hm_32 \
        $(PROJECT_HDR_DIR)/kernel/uapi \
        $(PROJECT_HDR_DIR)/kernel/kirin \
        $(PROJECT_HDR_DIR)/kernel/arch/$(ARCH)/uapi \
        $(PROJECT_HDR_DIR)/kernel/arch/$(ARCH) \
        $(PROJECT_SYS_INC)/kernel \
        $(PROJECT_SYS_INC)/TEE_ext \
    )

    ifeq ($(HI_PC_UT),true)
        include $(HIEPS_UT_WORK_DIR)/plat_dep.mk
        HI_PLAT_DEP_CFLAGS += -D__arm_ -DThreadUpdateCA=0 -Dhmobj_SPcanary=0 -DSPcanaryUpdate=0 -DTeecallRegister_Notify_Mem=0 -DTeecallSpi_Notify_Shadow=0 -DTeecallSpi_Notify_Wakeup=0 -DTeecallHm_Task_Update_Ca=0 -Dasm=__asm__
        PROJECT_INCLUDES := $(call hi-include-dir-add,\
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
            $(PROJECT_ROOT_DIR)/libs/libplatdrv/platform/kirin/mspc/test/ \
        )
    else
        HM_TOOLCHAIN_A32 := $(PROJECT_ROOT_DIR)/prebuild/toolchains/gcc-linaro-7.4.1-2019.02-x86_64_arm-eabi/bin
        include $(PROJECT_ROOT_DIR)/mk/toolchain.mk
        HI_PLAT_DEP_ARFLAGS := -rcs
        HI_PLAT_DEP_CFLAGS := -Wall -Wextra -march=armv8-a -marm -nostdinc -nodefaultlibs -fno-short-enums -fno-builtin-aligned_alloc -fno-builtin-alloca -fno-builtin-calloc -fno-builtin-fwrite -fno-builtin-fread -fno-builtin-fseek -fno-builtin-fclose -fno-builtin-malloc -fno-builtin-memcpy -fno-builtin-memcmp -fno-builtin-memset -fno-builtin-memmove -fno-builtin-realloc -fno-builtin-strncmp -fno-builtin-strlen -fno-builtin-strncpy -fno-builtin-strncat -fno-builtin-posix_memalign -fno-builtin-printf -fno-omit-frame-pointer -fno-peephole -fno-peephole2  -ffunction-sections  -fdata-sections -fPIC -fstack-protector-strong
        PROJECT_INCLUDES := $(call hi-include-dir-add,\
            $(PROJECT_HDR_DIR)/libc_32 \
            $(PROJECT_HDR_DIR)/libc_32/arch/$(ARCH) \
            $(PROJECT_HDR_DIR)/libc_32/arch/generic \
        )
    endif
    HI_PLAT_DEP_CFLAGS += $(PROJECT_INCLUDES)

    ifeq ($(HI_STATIC_CHECK),true)
        export HM_PLATFORM ?= kirin
        export TOPDIR ?= $(PROJECT_ROOT_DIR)
        export KIRIN_LIBS_DIR ?= $(PROJECT_ROOT_DIR)/libs
        export SOURCE_DIR ?= $(KIRIN_LIBS_DIR)/libplatdrv
        export chip_type ?= $(HI_CHIP_TYPE)
        export TARGET_BOARD_PLATFORM ?= $(HI_CHIP_NAME)
        PLATFORM_DIR ?= $(PROJECT_ROOT_DIR)/platform
        $(shell ln -sfT $(TOPDIR)/libs/libplatdrv/platform $(TOPDIR)/drivers/platdrv/platform)
        include $(PROJECT_ROOT_DIR)/prebuild/hm-teeos-release/headers/.config
        include $(PROJECT_ROOT_DIR)/config.mk
        include $(PROJECT_ROOT_DIR)/drivers/platdrv/Makefile
        HI_PLAT_DEP_CFLAGS += $(inc-flags)
        HI_PLAT_DEP_CFLAGS += $(c-flags)
        HI_PLAT_DEP_CFLAGS += $(flags) -Wno-unused-parameter
    endif
    # pclint
    ifeq ($(HI_PC_LINT), true)
        # clear warn in stdlib.h hmapi.h
        HI_PLAT_DEP_CFLAGS += -D_Noreturn -D__arm__
    endif
    # pc ut
    ifeq ($(HI_PC_UT), true)
        HI_PLAT_DEP_CFLAGS += $(HI_PLAT_DEP_INCLUDES)
        HI_PLAT_DEP_CXXFLAGS += $(call hi-include-dir-add, \
            $(HI_PLAT_ROOT_DIR)/custom/include \
        )
        HI_PLAT_DEP_INCLUDES :=
    endif
endif
