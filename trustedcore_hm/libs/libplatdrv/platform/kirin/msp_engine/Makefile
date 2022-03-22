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
    HI_BUILD_LIB_OUTSIDE := true
    HI_BUILD_OBJ_OUTSIDE := false
    ANDROID_TOP_ABS_DIR ?= $(abspath $(TOPDIR)/../../../../..)
    include $(dir $(lastword $(MAKEFILE_LIST)))set_env.mk

    #########################################################
    # build target
    #########################################################
    include $(HI_BUILD_DIR)/build.mk

    #########################################################
    # library
    #########################################################
    ifeq ($(HI_BUILD_LIB_OUTSIDE),true)
        SECENG_MAKE_ROOT_DIR := $(abspath $(HI_PLAT_ROOT_DIR)/../../..)
        HI_TMP_ALL_CFILES := $(sort $(patsubst $(SECENG_MAKE_ROOT_DIR)/%,%,$(filter $(SECENG_MAKE_ROOT_DIR)/%,$(HI_ALL_CFILES))))
        c-flags += $(HI_CFLAGS)
        c-flags += $(call hi-remove-repeat, $(LIBCRYPTO_INCLUDES), $(HI_PLAT_DEP_CFLAGS))
        CFILES += $(HI_TMP_ALL_CFILES)
        private_chip_type :=  $(if $(chip_type),$(chip_type),cs)
        private_out_dir := $(abspath $(HI_OUT_DIR))
        HI_OUT_LIBSECENG := $(private_out_dir)/libs/libseceng$(call hi-dft-suffix).a
        $(info HI_OUT_LIBSECENG=$(HI_OUT_LIBSECENG))

$(HI_OUT_LIBSECENG):
	$(NOECHO) mkdir -p $(dir $@)
	$(NOECHO) if [ -d $(HI_SECENG_ROOT_DIR) ]; then \
		echo "MSPE SOURCE COMPILE: $(HI_SECENG_ROOT_DIR)"; \
		$(HI_SECENG_ROOT_DIR)/cmake_make.sh \
			platform=teeos \
			build_variant=$(TARGET_BUILD_VARIANT) \
			chip=${TARGET_BOARD_PLATFORM} \
			chip_type=${private_chip_type} \
			build_dir=$(private_out_dir)/obj \
			install_dir=$(private_out_dir)/libs; \
	else \
		echo "MSPE BINARY COMPILE: $(HI_PUBLISH_LIBS_DIR)/libs/libseceng$(call hi-dft-suffix).a"; \
		cp -rf $(HI_PUBLISH_LIBS_DIR)/libs/libseceng$(call hi-dft-suffix).a $@; \
	fi

$(word 1, $(HI_TMP_ALL_CFILES)): $(HI_OUT_LIBSECENG)
    endif
endif
