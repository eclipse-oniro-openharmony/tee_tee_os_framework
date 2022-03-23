SECENG_LOCAL_MAKE := true
ifneq ($(filter %clean, $(MAKECMDGOALS)),)
    SECENG_LOCAL_MAKE := false
endif
ifeq ($(HI_SELF_MAKE),true)
    SECENG_LOCAL_MAKE := false
endif

ifeq ($(SECENG_LOCAL_MAKE),true)
    #########################################################
    # Environment initialize
    #########################################################
    HI_BUILD_LIB_OUTSIDE := $(if $(HM_PLATFORM),true,false)
    HI_BUILD_OBJ_OUTSIDE := $(HI_BUILD_LIB_OUTSIDE)
    ANDROID_TOP_ABS_DIR ?= $(abspath $(TOPDIR)/../../../..)
    include $(dir $(lastword $(MAKEFILE_LIST)))set_env.mk

    #########################################################
    # build target
    #########################################################
    include $(HI_BUILD_DIR)/build.mk

    #########################################################
    # library
    #########################################################
    ifeq ($(HI_BUILD_LIB_OUTSIDE),true)
        HI_TMP_ALL_CFILES := $(patsubst $(call hi-dir-abs, $(HI_PLAT_ROOT_DIR)/../../..)/%,%,$(HI_ALL_CFILES))
        c-flags += $(HI_CFLAGS)
        c-flags += $(HI_ALL_INCLUDES)
        CFILES += $(HI_TMP_ALL_CFILES)
    endif
endif
