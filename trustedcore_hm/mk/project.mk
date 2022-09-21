#
# FILE: project.mk
#

# ramdisk tools, run on host
# compile libs rules

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),mbedtls)
crypto_lib :=
else
crypto_lib :=
endif
libtee_shared_a32: libteeconfig libtimer libteeagentcommon libteeagentcommon_client libcrypto_hal libswcrypto_engine libac_policy $(crypto_lib) libteedynsrv
libtee_shared: libteeconfig libtimer libteeagentcommon libteeagentcommon_client libcrypto_hal libswcrypto_engine libac_policy $(crypto_lib) libteedynsrv

libbase_shared_a32: libteeconfig libtimer libteeagentcommon libteeagentcommon_client libcrypto_hal libswcrypto_engine libac_policy $(crypto_lib)
libbase_shared: libteeconfig libtimer libteeagentcommon libteeagentcommon_client libcrypto_hal libswcrypto_engine libac_policy $(crypto_lib)

libdrv_shared_a32: libteeconfig_a32
libdrv_shared: libteeconfig

libs: $(arm_libs) $(arm_sys_libs) $(arm_pro_libs) $(arm_chip_libs) $(aarch64_libs) $(vendor_libs) $(thirdparty_libs) $(host_tools)
	@echo "libsok"
$(arm_libs): $(arm_pro_libs) $(arm_sys_libs) $(arm_chip_libs)
	@echo "arm_lib_ok"
	@echo "building ARCH=arm libs=$@ target"
	$(VER) $(MAKE) -C sys_libs/$@ ARCH=arm -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "liblib"
$(arm_host_libs):
	@echo "building ARCH=arm_hostlibs=$@ target"
	$(VER) $(MAKE) -C $(if $(filter libhwsecurec_host,$@),thirdparty/huawei/$@,libs/$@) ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "arm_host_lib"
$(host_tools):$(arm_host_libs)
	@echo "building ARCH=arm_aarch64 host_tools= $@ target"
	$(VER) $(MAKE) -C tools/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "host_tools"
$(arm_pro_libs):
	@echo "building ARCH=arm_pro libs=$@ target"
	$(VER) $(MAKE) -C libs/$@ ARCH=arm TARG=_a32 -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "arm_pro_lib"
$(arm_sys_libs):
	@echo "building ARCH=arm sys_libs=$@ target"
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	echo "arm_sys_lib"
$(arm_chip_libs):$(arm_host_libs)
	@echo "building ARCH=arm_chip libs=$@ target"
	$(VER) $(MAKE) -C libs/$@ ARCH=arm -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "arm_chip_lib"
$(aarch64_libs): $(aarch64_sys_libs) $(aarch64_arm_chip_libs)
	@echo "building ARCH=aarch64 aarch64_libs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	@echo "aarch_lib"
$(aarch64_sys_libs):
	@echo "building ARCH=aarch64 libs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	echo "aarch_lib"
$(aarch64_arm_chip_libs):
	@echo "building ARCH=arm_chip_aarch64 libs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C libs/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C libs/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	@echo "aarch_lib"
$(vendor_libs):$(arm_chip_libs) $(aarch64_arm_chip_libs)
	@echo "building ARCH=aarch64 libs=$@ target"
	$(VER) $(MAKE) -C vendor/$(PLATFORM_NAME)/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all
	$(VER) $(MAKE) -C vendor/$(PLATFORM_NAME)/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "vendor_lib_64"

# compile ext_libs rules
ext_libs: $(arm_ext_libs) $(arm_vendor_ext_libs) $(arm_open_source_libs) $(aarch64_ext_libs) $(aarch64_open_source_libs) $(aarch64_vendor_ext_libs) $(aarch64_inner_ext_libs) $(thirdparty_libs)
	@echo "ext_lib"
$(arm_ext_libs):
	@echo "building ARCH=arm arm_ext_libs=$@ target"
	$(VER) $(MAKE) -C thirdparty/opensource/$@ ARCH=arm -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "arm_ext_lib"
$(arm_vendor_ext_libs): link_aarch64_libs
	@echo "building ARCH=arm arm_vendor_ext_libs=$@ target"
	$(VER) $(MAKE) -C thirdparty/vendor/$@ ARCH=arm -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "arm_vendor_ext_lib"
$(arm_open_source_libs):
	@echo "building ARCH=arm arm_open_source_libs=$@ target"
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	@echo "arm_open_source_lib"
$(aarch64_ext_libs):
	@echo "building ARCH=aarch64 ext_lib=$@ target"
	$(VER) $(MAKE) -C thirdparty/opensource/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "aarch_ext_lib"
$(aarch64_vendor_ext_libs):
	@echo "building ARCH=aarch64 ext_lib=$@ target"
	$(VER) $(MAKE) -C thirdparty/vendor/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "aarch64_vendor_ext_lib"
$(aarch64_inner_ext_libs):
	@echo "building ARCH=aarch64 ext_lib=$@ target"
	$(VER) $(MAKE) -C thirdparty/huawei/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all
	@echo "aarch64_inner_ext_lib"
$(aarch64_open_source_libs):
	@echo "building ARCH=aarch64 ext_lib=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C sys_libs/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	@echo "aarch64_open_source_lib"
$(thirdparty_libs):
	echo "building ARCH=arm_chip_aarch64 libs=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C thirdparty/huawei/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) $(MAKE) -C thirdparty/huawei/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	echo "thirdparty_libs"

# compile drivers rules

drivers: $(arm_frm_drivers) $(arm_driver_drivers) $(aarch64_frm_drivers) $(aarch64_driver_drivers) $(arm_test_drivers) $(aarch64_test_drivers)
$(arm_frm_drivers): $(arm_sys_libs)  $(arm_pro_libs) $(arm_chip_libs) link_arm_libs link_aarch64_libs frameworks
	@echo "building ARCH=arm driver=$@ target"
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C framework/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring hmsysmgr,$@)$(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C framework/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
$(arm_driver_drivers): $(arm_sys_libs)  $(arm_pro_libs) $(arm_chip_libs) link_arm_libs link_aarch64_libs
	@echo "building ARCH=arm driver=$@ target"
	$(VER) LDFLAGS= $(MAKE) -C drivers/$@ ARCH=arm TARG=_a32 -f $(PREBUILD_HEADER)/.config -f Makefile all
$(arm_test_drivers): $(arm_sys_libs)  $(arm_pro_libs) $(arm_chip_libs) link_arm_libs link_aarch64_libs
	@echo "building ARCH=arm driver=$@ target"
	$(VER) LDFLAGS= $(MAKE) -C tests/$@ ARCH=arm -f $(PREBUILD_HEADER)/.config -f Makefile all
$(aarch64_frm_drivers): $(aarch64_libs) $(arm_sys_libs) link_aarch64_libs link_arm_libs frameworks
	@echo "building ARCH=aarch64 driver=$@ target"
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C framework/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring hmsysmgr,$@)$(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C framework/$@ ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
$(aarch64_driver_drivers): $(aarch64_libs) link_aarch64_libs link_arm_libs
	@echo "building ARCH=aarch64 driver=$@ target"
	$(VER) LDFLAGS= $(MAKE) -C drivers/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all
$(aarch64_test_drivers): $(aarch64_libs) link_aarch64_libs link_arm_libs
	@echo "building ARCH=aarch64 driver=$@ target"
	$(VER) LDFLAGS= $(MAKE) -C tests/$@ ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all

frameworks:
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C ../framework/gtask ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C ../framework/gtask ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C ../framework/teesmcmgr ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C ../framework/teesmcmgr ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring true, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C ../framework/drvmgr ARCH=arm TARG=_a32 USE_GNU_CXX=y -f $(PREBUILD_HEADER)/.config -f Makefile all)
	$(if $(findstring false, $(CONFIG_SUPPORT_64BIT)), ,$(VER) LDFLAGS= $(MAKE) -C ../framework/drvmgr ARCH=aarch64 -f $(PREBUILD_HEADER)/.config -f Makefile all)

# compile kernel rules

kernel: $(hm_kernel) $(hm_elfloader)
$(hm_elfloader):
	@mkdir -p $(ELFLOADER_OUTDIR)
	@echo "compile elfloader ELFLOADER_OUTDIR is $(ELFLOADER_OUTDIR)"
	$(VER) LDFLAGS= $(MAKE) -C kernel/$@ -f $(PREBUILD_HEADER)/.config -f Makefile \
		HAVE_AUTOCONF=1 NO_PRESERVE_TIMESTAMP=1 all

$(hm_kernel):
	@mkdir -p $(KERNEL_OUTDIR)
	@echo "compile elfloader KERNEL_OUTDIR is $(KERNEL_OUTDIR)"
	$(VER) LDFLAGS= $(MAKE) -C $@/ ARCH=arm -f $(PREBUILD_HEADER)/.config -f Makefile \
		HAVE_AUTOCONF=1 NO_PRESERVE_TIMESTAMP=1 KERNEL_SOURCE_ROOT=$(KERNEL_ROOT_PATH) all


COMPARE_IMAGE := 0
WITH_LOG_ENCODE := false

# Add boot-apps here
# NOTE: boot-apps will package to kernel.elf do not need to change
boot-apps := $(OUTPUTDIR)/$(TEE_ARCH)/apps/hmfilemgr
boot-apps += $(OUTPUTDIR)/$(TEE_ARCH)/drivers/hmsysmgr

HM_APPS_TOOLS := $(TOPDIR)/tools
HM_APPS_LIBCPIO := $(TOPDIR)/sys_libs/libcpio

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
	$(VER) $(TOOLS)/smart-strip.sh $(boot-apps)
	$(VER) DDK_FLAG=$(DDK_FLAG) CONFIG_NO_PLATCFG_EMBEDDED=$(CONFIG_NO_PLATCFG_EMBEDDED) PREBUILD_DIR=$(PREBUILD_DIR) ELFLOADER_DIR=$(ELFLOADER_OUTDIR) OUTPUTDIR=$(OUTPUTDIR)\
		KERNEL_OUTDIR=$(KERNEL_OUTDIR) $(TOOLS)/gen_boot_image.sh $(KERNEL_OUTDIR)/kernel.elf $(boot-apps) $@ 2>&1 \
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
	$(VER) IMAGE_ROOT=$(STAGE_DIR) $(TOOLS)/packimg.sh \
		$(TRUSTEDCORE_PLATFORM_CHOOSE) \
		$(COMPARE_IMAGE) \
		$(TRUSTEDCORE_CHIP_CHOOSE) \
		$(WITH_TEEOS_ENCRYPT) \
		$(WITH_LOG_ENCODE)
ifneq ($(CODE_CHECKER),y)
	$(VER) $(TOPDIR)/../../tee_os_kernel/libs/syslib/libc/clean_libc.sh  $(TOPDIR)/../../tee_os_kernel
	$(VER) $(TOPDIR)/../../tee_os_kernel/libs/teelib/libopenssl/clean_openssl.sh $(TOPDIR)/../../tee_os_kernel

endif
ifneq ($(VERSION_DDK),y)
	$(VER) rm -rf $(TOPDIR)/tools/cpio-strip/cpio-strip
endif

include mk/svc-flags.mk

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
include $(TOPDIR)/mk/bootfs.mk
