#
# FILE: project.mk
#

# ramdisk tools, run on host
# compile libs rules

include $(BUILD_CONFIG)/arch_config.mk
libtee_shared_a32: libteeconfig libtimer libteeagentcommon_client libcrypto_hal libswcrypto_engine $(crypto_lib) libteedynsrv
libtee_shared: libteeconfig libtimer libteeagentcommon_client libcrypto_hal libswcrypto_engine $(crypto_lib) libteedynsrv

libdrv_shared_a32: libteeconfig_a32
libdrv_shared: libteeconfig

teelib := libcrypto_hal libtimer libagent libagent_base libhmdrv libteeos libpermission_service \
	libswcrypto_engine libtaentry libteeagentcommon_client libcrypto libteeconfig libteemem libssa libhuk libteedynsrv
syslib := libelf_verify libspawn_common libelf_verify_key libdynconfmgr libdynconfbuilder
drvlib := libdrv_frame

libs: libtee_shared libdrv_shared ramfsmkimg_host $(syslib)
	@echo "libsok"

libhwsecurec_host:
	@echo "building libhwsecurec_host"
	$(VER) $(MAKE) -C $(THIRDPARTY_LIBS)/$@ -f $(PREBUILD_HEADER)/.config -f Makefile all

ramfsmkimg_host: libhwsecurec_host
	@echo "building ramfsmkimg_host"
	$(VER) $(MAKE) -C $(BUILD_TOOLS)/$@ -f $(PREBUILD_HEADER)/.config -f Makefile all

$(teelib):
	@echo "building teelibs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

$(drvlib):
	@echo "building drvlibs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/common/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/common/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

$(syslib):
	@echo "bulding syslibs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(SYSLIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(SYSLIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

libtee_shared: $(teelib)
	@echo "building libtee_shared target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(TEELIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

libdrv_shared: $(drvlib)
	@echo "building libdrv_shared target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C $(DRVLIB)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)

# compile drivers rules

frameworks := gtask teesmcmgr drvmgr tarunner
service := huk_service

ifdef CONFIG_SSA_64BIT
service += ssa
endif

ifdef CONFIG_PERMSRV_64BIT
service += permission_service
endif

drivers := crypto_mgr

ifdef CONFIG_TEE_MISC_DRIVER_64BIT
drivers += tee_misc_driver
endif

$(drivers):
	@echo "building ARCH=arm driver=$@ target"
	$(VER) LDFLAGS= $(MAKE) -C $(DRIVERS_PATH)/$@ ARCH=arm TARG=_a32 -f $(PREBUILD_HEADER)/.config -f Makefile all
	$(VER) LDFLAGS= $(MAKE) -C $(DRIVERS_PATH)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all

$(frameworks):
	@echo "tee_os_framework framework compile $@"
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(FRAMEWORK_PATH)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(FRAMEWORK_PATH)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)

$(service):
	@echo "tee_os_framework service compile $@"
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(SERVICES_PATH)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C $(SERVICES_PATH)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)

COMPARE_IMAGE := 0
WITH_LOG_ENCODE := false

# Add boot-apps here
# NOTE: boot-apps will package to kernel.elf do not need to change
boot-apps := $(OUTPUTDIR)/$(TEE_ARCH)/apps/hmfilemgr
boot-apps += $(PREBUILD_LIBS)/$(TEE_ARCH)/hmsysmgr

HM_APPS_TOOLS := $(BUILD_TOOLS)/generate_img
HM_APPS_LIBCPIO := $(TOPDIR)/../tee_os_kernel/libs/syslib/libcpio

.PHONY : cpio-strip
cpio-strip :
	@echo "[$@] building..."
	$(Q)$(MAKE) $(MAKE_SILENT) -C $(HM_APPS_TOOLS)/$@ -f $(HM_APPS_TOOLS)/$@/Makefile \
        SOURCE_DIR=$(HM_APPS_TOOLS)/$@ -Wall -Wextra \
        LIBCPIO_BASE=$(HM_APPS_LIBCPIO) \
        HM_APPS_DIR=$(TOPDIR)
	@echo "[$@] done"

DDK_FLAG:=false
$(STAGE_DIR)/teehm.img.elf: $(ELFLOADER_OUTDIR)/elfloader.o hmfilemgr cpio-strip
	@echo "[GEN_IMAGE] $@"
	$(VER) $(BUILD_TOOLS)/generate_img/smart-strip.sh $(boot-apps)
	$(VER) DDK_FLAG=$(DDK_FLAG) CONFIG_NO_PLATCFG_EMBEDDED=$(CONFIG_NO_PLATCFG_EMBEDDED) PREBUILD_DIR=$(PREBUILD_DIR) ELFLOADER_DIR=$(ELFLOADER_OUTDIR) OUTPUTDIR=$(OUTPUTDIR)\
		KERNEL_OUTDIR=$(KERNEL_OUTDIR) BUILD_TOOLS=$(BUILD_TOOLS) $(BUILD_TOOLS)/generate_img/gen_boot_image.sh $(KERNEL_OUTDIR)/kernel.elf $(boot-apps) $@ 2>&1 \
		| while read line; do echo " [GEN_IMAGE] $$line"; done; \
		exit ${PIPESTATUS[0]}

$(STAGE_DIR)/teehm.img: $(STAGE_DIR)/teehm.img.elf
	@echo "[OBJCOPY $@]"
	$(VER) $(OBJCOPY) -O binary $< $@
ifeq ($(CONFIG_QEMU_PLATFORM),y)
	cp $(STAGE_DIR)/teehm.img  $(STAGE_DIR)/bl32.bin
endif

$(STAGE_DIR)/trustedcore.img: $(STAGE_DIR)/teehm.img
	@echo "[Installing $@]"
	$(VER) IMAGE_ROOT=$(STAGE_DIR) $(BUILD_TOOLS)/pack_img/packimg.sh \
		$(TRUSTEDCORE_PLATFORM_CHOOSE) \
		$(COMPARE_IMAGE) \
		$(TRUSTEDCORE_CHIP_CHOOSE) \
		$(WITH_TEEOS_ENCRYPT) \
		$(WITH_LOG_ENCODE)
ifneq ($(CODE_CHECKER),y)
	$(VER) $(TOPDIR)/../tee_os_kernel/libs/syslib/libc/clean_libc.sh  $(TOPDIR)/../tee_os_kernel
	$(VER) $(TOPDIR)/../tee_os_kernel/libs/teelib/libopenssl/clean_openssl.sh $(TOPDIR)/../tee_os_kernel

endif
ifneq ($(VERSION_DDK),y)
	$(VER) rm -rf $(BUILD_TOOLS)/generate_img/cpio-strip/cpio-strip
endif

include $(BUILD_SERVICE)/svc-flags.mk

# export for tools/gen_boot_image.sh
ifeq (${HM_ARCH}, aarch32)
	HM_TARGET_ARCH := $(TARGET_ARCH_32)
else
	HM_TARGET_ARCH := $(TARGET_ARCH_64)
endif
GENERAL_OPTIONS := -Wdate-time -Wfloat-equal -Wshadow -fsigned-char -fno-strict-aliasing \
                   -pipe -fno-common
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))

SDK_CPPFLAGS := $(flags) $(c-flags) -I$(PREBUILD_DIR)/headers -I$(PREBUILD_DIR)/headers/ddk/legacy -I$(PREBUILD_DIR)/headers/sys/hmapi -I$(PREBUILD_DIR)/headers/sys/hmapi/kernel -I$(PREBUILD_DIR)/headers/sys/legacy -I$(PREBUILD_DIR)/headers/ddk/hmapi
SDK_CPPFLAGS := $(filter-out --target=$(TARGET_ARCH), $(SDK_CPPFLAGS))
SDK_CPPFLAGS += --target=$(HM_TARGET_ARCH)
SDK_CPPFLAGS := $(call uniq, $(SDK_CPPFLAGS) $(GENERAL_OPTIONS))
SDK_CPPFLAGS := $(filter-out -fsanitize=cfi, $(SDK_CPPFLAGS))
SDK_CPPFLAGS := $(filter-out -flto, $(SDK_CPPFLAGS))
SDK_CPPFLAGS += -include$(PREBUILD_DIR)/headers/autoconf.h
export SDK_CPPFLAGS

# bootfs image
include $(BUILD_PACK)/bootfs.mk
