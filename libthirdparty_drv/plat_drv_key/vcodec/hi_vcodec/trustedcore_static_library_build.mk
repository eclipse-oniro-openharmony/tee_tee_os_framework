# add by l00202565

## this set trustedcore_src build toolchain
#0. default use android toolchain
# android 4.0/4.4 ARCH_PREFIX is arm; in android 5.0 ARCH_PREFIX can be arm/aarch64
$(info PLATFORM_VERSION: $(PLATFORM_VERSION))
$(info TRUSTEDCORE_ARCH_CHOOSE: $(TRUSTEDCORE_ARCH_CHOOSE))
LOCAL_GCC_PATH :=./prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/bin
#LOCAL_GCC_PATH :=./vendor/thirdparty/secure_os/trustedcore_hm/libs/libplatdrv/platform/kirin/vcodec/hi_vcodec/arm-linux-androideabi-4.9/bin
ifeq ($(strip $(TRUSTEDCORE_ARCH_CHOOSE)), AARCH64)
#used when trustedcore support 64bit
LOCAL_CC := $(TARGET_CC)
TRUSTECORE_TARGET_AR := $(TARGET_AR)
else
ifneq ($(filter 4.% 4.%.%, $(PLATFORM_VERSION)),)
LOCAL_CC := $(TARGET_CC)
TRUSTECORE_TARGET_AR := $(TARGET_AR)
else
LOCAL_CC := $(LOCAL_GCC_PATH)/arm-linux-androideabi-gcc
TRUSTECORE_TARGET_AR :=$(LOCAL_GCC_PATH)/arm-linux-androideabi-ar
endif
endif

#1. set arm-linux-androideabi-4.8 toolchain
#LOCAL_CC := prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.8/bin/arm-linux-androideabi-gcc
#TRUSTECORE_TARGET_AR := prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.8/bin/arm-linux-androideabi-ar

#2. arm-eabi toolchain
#LOCAL_CC := arm-eabi-gcc
#TRUSTECORE_TARGET_AR := arm-eabi-ar

#3. set arm-linux-androideabi-4.6 toolchain
#LOCAL_CC := prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.6/bin/arm-linux-androideabi-gcc
#TRUSTECORE_TARGET_AR := prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.6/bin/arm-linux-androideabi-ar


#toolchain info
$(info LOCAL_CC: $(LOCAL_CC))
$(info TRUSTECORE_TARGET_AR: $(TRUSTECORE_TARGET_AR))

include $(TRUSTEDCORE_MK)/build_flags.mk

define trustedcore-transform-o-to-static-lib
@mkdir -p $(dir $@)
@rm -f $@
$(extract-and-include-target-whole-static-libs)
@echo "target StaticLib: $(PRIVATE_MODULE) ($@)"
$(call split-long-arguments,$(TRUSTECORE_TARGET_AR) \
    crsPD \
    $(PRIVATE_ARFLAGS) $@,$(filter %.o, $^))
endef

ifeq ($(strip $(LOCAL_MODULE_CLASS)),)
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
endif
ifeq ($(strip $(LOCAL_MODULE_SUFFIX)),)
LOCAL_MODULE_SUFFIX := .a
endif
LOCAL_UNINSTALLABLE_MODULE := true
ifneq ($(strip $(LOCAL_MODULE_STEM)$(LOCAL_BUILT_MODULE_STEM)),)
$(error $(LOCAL_PATH): Cannot set module stem for a library)
endif

include $(BUILD_SYSTEM)/binary.mk
LOCAL_RAW_STATIC_LIBRARY:=
$(all_objects) : PRIVATE_TARGET_PROJECT_INCLUDES :=
$(all_objects) : PRIVATE_TARGET_C_INCLUDES :=
$(all_objects) : PRIVATE_TARGET_GLOBAL_CFLAGS :=
$(all_objects) : PRIVATE_TARGET_GLOBAL_CPPFLAGS :=
$(all_objects) : PRIVATE_CFLAGS_NO_OVERRIDE :==int-to-pointer-cast

$(LOCAL_BUILT_MODULE) : $(built_whole_libraries)
$(LOCAL_BUILT_MODULE) : $(all_objects)
	$(trustedcore-transform-o-to-static-lib)
