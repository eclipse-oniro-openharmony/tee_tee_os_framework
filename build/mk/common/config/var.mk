# basic dirs, these variables will be used by whole project
override BUILD_DIR     := $(OUTPUTDIR)/$(ARCH)/obj/$(ARCH)/$(MODULE_FOLDER)
override LIB_DIR       := $(OUTPUTDIR)/$(ARCH)/libs
ifeq ($(CONFIG_ARCH_AARCH32),y)
override LIB_DIR_A32   := $(OUTPUTDIR)/arm/libs
endif
override APP_DIR       := $(OUTPUTDIR)/$(ARCH)/apps
override DRV_DIR       := $(OUTPUTDIR)/$(ARCH)/drivers
override HDR_L_DIR     := $(OUTPUTDIR)/headers
override KERNEL_OUTDIR := $(OUTPUTDIR)/kernel
override ELFLOADER_OUTDIR := $(OUTPUTDIR)/elfloader

ifneq ($V,)
VER :=
else
VER := @
endif

# kernel header do not relative with arch
KERNEL_HDR_DIR := $(OUTPUTDIR)/kernel/headers

ifeq ($(PREBUILD_ROOT),)
override PREBUILD_ROOT := $(TOPDIR)/prebuild
endif

### prebuild directory:
PREBUILD_DIR    := $(PREBUILD_ROOT)/$(HM_SDK_VER)
PREBUILD_HEADER := $(PREBUILD_DIR)/headers
PREBUILD_LIBS   := $(PREBUILD_DIR)/libs
PREBUILD_TOOLS  := $(PREBUILD_DIR)/tools
PREBUILD_APPS   := $(PREBUILD_DIR)/apps
PREBUILD_KERNEL_LIBS := $(PREBUILD_DIR)/kernel

PREBUILD_LIBC_INC   := $(PREBUILD_HEADER)/libc
PREBUILD_CXX_INC    := $(PREBUILD_HEADER)/c++

PREBUILD_ARCH_PLAT_LIBS := $(PREBUILD_LIBS)/$(ARCH)

## package directory:
STAGE_DIR := $(OUTPUTDIR)/stage

-include $(PREBUILD_HEADER)/.config

# selection of platform

ifeq ($(strip $(QUICK_BOOT_CHK)), true)
WITH_TEEOS_ENCRYPT := false
else
WITH_TEEOS_ENCRYPT := true
endif

ifeq ($(TARGET_BUILD_VARIANT),eng)
	WITH_ENG_VERSION = true
else
	WITH_ENG_VERSION = false
endif


ifeq ($(WITH_ENG_VERSION), true)
	TRUSTEDCORE_PLATFORM_FLAGS += -DSECMEM_UT
endif

ifeq ($(RELEASE_SIGN), true)
	TRUSTEDCORE_PLATFORM_FLAGS += -DRELEASE_SIGN_BUILD_TEE
endif

SECUREC_LIB := $(TEE_SECUREC_DIR)/include
