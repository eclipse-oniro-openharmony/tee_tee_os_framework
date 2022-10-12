ifneq ($V,)
VER :=
else
VER := @
endif

## hm-sdk directories:
export TOPDIR := $(CURDIR)
export TOOLS      := $(TOPDIR)/tools
export TOOLS_ROOT := $(TOPDIR)/prebuild/$(HM_SDK_VER)/tools
export VER
export LIBS_DIR := $(TOPDIR)/libs
export APPS_DIR := $(TOPDIR)/apps
export PLATFORM_DIR := $(TOPDIR)/platform
export TEELIB := $(TOPDIR)/../lib/teelib
export DRVLIB := $(TOPDIR)/../lib/drvlib
export FRAMEWORK_PATH := $(TOPDIR)/../framework
export SYSLIB := $(TOPDIR)/../lib/syslib
export K_TEELIB := $(TOPDIR)/../../tee_os_kernel/libs/teelib
export K_SYSLIB := $(TOPDIR)/../../tee_os_kernel/libs/syslib
export SERVICES_PATH := $(TOPDIR)/../services
export DRIVERS_PATH := $(TOPDIR)/../drivers

## if O=xxx, using outsize output directory.
ifneq ($(O),)
export OUTPUTDIR := $(O)
else
export OUTPUTDIR := $(TOPDIR)/output
endif
include config.mk

PHONY += default
default: all

# top directory use aarch64
ARCH = aarch64
include $(TOPDIR)/mk/var.mk
include $(TOPDIR)/mk/plat.mk
export PLAT_CFG_DIR := $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/plat_cfg
export PLAT_COMMON_DIR := $(PLATFORM_DIR)/common
ifneq ($(strip $(TARGET_BOARD_PLATFORM)), )
ifeq ($(LIBS_INSTALL_DIR),)
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/platform.mk
endif
endif
include $(TOPDIR)/mk/toolchain.mk
-include $(PREBUILD_HM_INC)/.config
include $(TOPDIR)/mk/project.mk

# for install header
ifeq ($(HDR_INSTALL_DIR),)
HDR_INSTALL_DIR:=$(HDR_L_DIR)
$(shell test -d $(HDR_INSTALL_DIR) || mkdir -p $(HDR_INSTALL_DIR))
endif

ifeq ($(CONFIG_GCC_PLUGINS), y)
GCC_PLUGIN := gcc-plugins
HM_APPS_GCC_PLUGINS_PATH := $(TOPDIR)
include $(HM_APPS_GCC_PLUGINS_PATH)/tools/gcc-plugins/mk/gcc-plugins.mk
else
GCC_PLUGIN :=
endif
export GCC_PLUGIN

# default target
PHONY += ext_libs libs kernel drivers apps package open_source_libs
all: $(GCC_PLUGIN) $(RT_LIB) install_headers setup_links kernel ext_libs libs drivers apps package open_source_libs
tees: kernel setup_links ext_libs libs drivers apps open_source_libs
drivers: setup_links ext_libs libs link_libs open_source_libs
apps: setup_links ext_libs libs link_libs open_source_libs
package: hmfilemgr
mods: drv_mods

PHONY += link_libs link_arm_libs link_aarch64_libs
link_libs: link_arm_libs link_aarch64_libs
link_arm_libs: libs ext_libs open_source_libs
	@echo "[link] libs=$(libs) ext_libs=$(ext_libs) open_source_libs=$(open_source_libs)"
	$(VER) PBD=$(PREBUILD_LIBS)/arm/ ; \
	for lib in `ls $$PBD`; do \
		link=$(OUTPUTDIR)/arm/libs/$$lib ; \
		f=$$PBD/$$lib ; \
		if [ ! -L $$link ] && [ ! -e $$link ] ; then \
			ln -s $$f $$link && \
			echo "link prebuild library: $$link" ; \
		fi \
	done
link_aarch64_libs: libs ext_libs
	@echo "[link] aarch libs=$(libs) ext_libs=$(ext_libs)"
	$(VER) PBD=$(PREBUILD_LIBS)/aarch64/ ; \
	for lib in `ls $$PBD`; do \
		link=$(OUTPUTDIR)/aarch64/libs/$$lib ; \
		f=$$PBD/$$lib ; \
		if [ ! -L $$link ] && [ ! -e $$link ] ; then \
			ln -s $$f $$link && \
			echo "link prebuild library: $$link" ; \
		fi \
	done

## setup & clean directory symbol-links, to compatible with CI circle-complexity
setup_links:

clean_links:

## install headers:
install_headers: setup_links $(HDR_INSTALL_DIR)/.timestamp
$(HDR_INSTALL_DIR)/.timestamp:
	@echo "before armsys ${EXPORT_HDRS} arm_sys_libs=$(arm_sys_libs) arm_libs=$(arm_libs)"
	$(VER) for l in $(arm_sys_libs); do \
		($(MAKE) -C sys_libs/$$l ARCH=arm HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done;
	@echo "before armpro ${EXPORT_HDRS} arm_pro_libs=$(arm_pro_libs)"
	$(VER) for l in $(arm_pro_libs); do \
		($(MAKE) -C libs/$$l ARCH=arm HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done;
	@echo "before armchip ${EXPORT_HDRS} arm_chip_libs=$(arm_chip_libs)"
	$(VER) for l in $(arm_chip_libs); do \
		($(MAKE) -C libs/$$l ARCH=arm HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done;
	@echo "before aarch64-sys-lib ${EXPORT_HDRS} aarch64_sys_libs=$(aarch64_sys_libs) aarch64_libs=$(aarch64_libs)"
	$(VER) for l in $(aarch64_sys_libs); do \
		($(MAKE) -C sys_libs/$$l ARCH=aarch64 HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done;
	@echo "before aarch64-armchip-lib ${EXPORT_HDRS} aarch64_arm_chip_libs=$(aarch64_arm_chip_libs)"
	$(VER) for l in $(aarch64_arm_chip_libs); do \
		($(MAKE) -C libs/$$l ARCH=aarch64 HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done;
	@echo "before armext-lib ${EXPORT_HDRS} arm_ext_libs=$(arm_ext_libs)"
	$(VER) for l in $(arm_ext_libs); do \
		($(MAKE) -C thirdparty/opensource/$$l ARCH=arm HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done
	@echo "before opensorce-lib ${EXPORT_HDRS} arm_open_source_libs=$(arm_open_source_libs)"
	$(VER) for l in $(arm_open_source_libs); do \
		($(MAKE) -C sys_libs/$$l ARCH=arm TARG=_a32 HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done
	@echo "before aarch64ext-lib ${EXPORT_HDRS} aarch64_ext_libs=$(aarch64_ext_libs)"
	$(VER) for l in $(aarch64_ext_libs); do \
		($(MAKE) -C thirdparty/opensource/$$l ARCH=aarch64 HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done
	@echo "before opensorce-lib ${EXPORT_HDRS} aarch64_open_source_libs=$(aarch64_open_source_libs)"
	$(VER) for l in $(aarch64_open_source_libs); do \
		($(MAKE) -C sys_libs/$$l ARCH=aarch64 HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done
	@echo "before tools ${EXPORT_HDRS}"
	$(VER) if [ -f "$(PLATFORM_DIR)/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg/plat_cfg.h" ] ; then \
	cp $(PLATFORM_DIR)/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg/plat_cfg.h $(HDR_INSTALL_DIR)/; fi;
	touch $(HDR_INSTALL_DIR)/.timestamp
	@echo "before lib/teelib ${EXPORT_HDRS}"
	$(VER) for l in $(teelib); do \
		($(MAKE) -C $(TEELIB)/$$l HDR_INSTALL_DIR=$(HDR_INSTALL_DIR) install_headers;) \
	done

## install libs:
install_libs:
	@for l in $(OUTPUTDIR)/arm/libs/* $(OUTPUTDIR)/aarch64/libs/*; do \
		if [ -e $$l ] && [ ! -L $$l ]; then cp -rf $$l $(LIBS_INSTALL_DIR); fi; \
	done

# packaging the image
PHONY += hmfilemgr
hmfilemgr: $(OUTPUTDIR)/$(TEE_ARCH)/apps/hmfilemgr
$(STAGE_DIR)/bootfs.img:
$(OUTPUTDIR)/$(TEE_ARCH)/apps/hmfilemgr: $(STAGE_DIR)/bootfs.img
	@echo "Building hmfilemgr"
	$(MAKE) -C tools/hmfilemgr ARCH=$(TEE_ARCH) -j

PHONY += teehm.img trustedcore.img
package: $(STAGE_DIR)/trustedcore.img

PHONY += release
release:
	@echo "!!compile release"
	sh $(TOPDIR)/tools/ddk/generate_sdk.sh
	sh $(TOPDIR)/tools/ddk/gener_tee_sdk.sh
	sh $(TOPDIR)/tools/ddk/gener_mk_sdk.sh
	@rm -rf tools/elf_extract

PHONY += clean
clean: clean_links
	@rm -rf $(OUTPUTDIR)
	@rm -rf sec_trustedcore.img
	@rm -rf tools/linker.lds_pp
	@rm -rf prebuild/hm-teeos-release/tools/ramfsmkimg
clober: clean
	@rm -rf prebuild/toolchains

help:
	@echo " "
	@echo "hm-sdk project Makefile:"
	@echo " Variables: "
	@echo "   V=1      : 'V' is not set by default, Makefile will print less information."
	@echo "              input \"make V=1\" will print more compile information"
	@echo " "
	@echo " Targets:"
	@echo "   all      : default compile target, will compile all the libs, apps, and package the Image"
	@echo "              will generate libs & apps & object files to output folder"
	@echo " "
	@echo "   prebuild : download the toolchain from linaro website(later maybe compile the toolchain ourselves)."
	@echo "              and then compile llvm c++ libraries."
	@echo "              all the packages are under \"prebuild/toolchains\" folder, TA or Kernel could use it directly."
	@echo " "
	@echo "              NOTE: now we have used 3 toolchains:"
	@echo "              1. arm-eabi : to compile 32 bit ARM TA, and most of the libs apps without C++ supported"
	@echo "              2. arm-linux-gnueabi: to compile 32 bit ARM TA with llvm c++ supported."
	@echo "                 as llvm must be compiled with gnueabi target.(maybe fix it later)"
	@echo "              3. aarch64-linux-gnu: to compile 64 bit ARM apps, kernel"
	@echo " "
	@echo "   clean    : only clean the output folder"
	@echo " "
	@echo "   clober   : clean output & prebuild toolchain folders"
	@echo " "

.PHONY: $(PHONY)
