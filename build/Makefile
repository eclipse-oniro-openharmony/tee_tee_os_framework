# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
ifneq ($V,)
VER :=
else
VER := @
endif

## hm-sdk directories:
export TOPDIR := $(CURDIR)/../
export OPENSSL_DIR := $(CURDIR)/../../../../third_party/openssl_1.1.1n
export OLD_TOPDIR := $(TOPDIR)/config
export TOOLS      := $(TOPDIR)/build/tools
export TOOLS_ROOT := $(TOPDIR)/prebuild/$(HM_SDK_VER)/tools
export VER
export PLATFORM_DIR := $(OLD_TOPDIR)/platform
export TEELIB := $(TOPDIR)/lib/teelib
export DRVLIB := $(TOPDIR)/lib/drvlib
export FRAMEWORK_PATH := $(TOPDIR)/framework
export SYSLIB := $(TOPDIR)/lib/syslib
export K_TEELIB := $(TOPDIR)/../tee_os_kernel/libcore_shared/teelib
export K_SYSLIB := $(TOPDIR)/../tee_os_kernel/libcore_shared/syslib
export SERVICES_PATH := $(TOPDIR)/services
export DRIVERS_PATH := $(TOPDIR)/drivers
export K_THIRDPARTY := $(TOPDIR)/../tee_os_kernel/libcore_shared/thirdparty
export THIRDPARTY_LIBS := $(TOPDIR)/lib/thirdparty
export CONFIG_PATH := $(TOPDIR)/config

export BUILD_TOOLS := $(TOPDIR)/build/tools
export BUILD_PACK := $(TOPDIR)/build/mk/pack
export BUILD_LIB := $(TOPDIR)/build/mk/lib_common
export BUILD_SERVICE := $(TOPDIR)/build/mk/service_common
export BUILD_DRIVER := $(TOPDIR)/build/mk/driver_common
export BUILD_FRAMEWORK := $(TOPDIR)/build/mk/framework_common
export BUILD_CFI := $(TOPDIR)/build/mk/common/cfi
export BUILD_CONFIG := $(TOPDIR)/build/mk/common/config
export BUILD_OPERATION := $(TOPDIR)/build/mk/common/operation

## if O=xxx, using outsize output directory.
ifneq ($(O),)
export OUTPUTDIR := $(O)
else
export OUTPUTDIR := $(TOPDIR)/output
endif

HM_BOOTFS_SIZE ?= "8000K"
export HM_SDK_VER := tee-kernel-release

PHONY += default
default: all

# top directory use aarch64
ARCH = aarch64
include $(BUILD_CONFIG)/var.mk
include $(BUILD_CONFIG)/plat_config_file.mk

PHONY += GEN_CONF_FILE
GEN_CONF_FILE:
	echo "generated platautoconf.h "
	rm -rf $(PLAT_AUTOCONF_FILE)
	test -d $(PREBUILD_DIR)/headers || mkdir -p $(PREBUILD_DIR)/headers
	touch $(PLAT_AUTOCONF_FILE)
	grep '.*=.*' < $(CONFIG_FILE) > $(PLAT_AUTOCONF_FILE)
	sed -i '1i\#define PLAT_AUTO_CONFIG_H' $(PLAT_AUTOCONF_FILE)
	sed -i '1i\#ifndef PLAT_AUTO_CONFIG_H' $(PLAT_AUTOCONF_FILE)
	sed -i -r 's/(.*)=y/#define \1\t1/g' $(PLAT_AUTOCONF_FILE)
	sed -i -r '/(.*)=n/d' $(PLAT_AUTOCONF_FILE)
	sed -i -r 's/(.*)=(.*)/#define \1\t\2/g' $(PLAT_AUTOCONF_FILE)
	sed -i '$$a\#endif /* AUTO_CONFIG_H */'  $(PLAT_AUTOCONF_FILE)
	echo -e >> $(PREBUILD_DIR)/headers/.config
	cat $(CONFIG_FILE) | tee -a $(PREBUILD_DIR)/headers/.config

-include $(PREBUILD_HM_INC)/.config
export PLAT_CFG_DIR := $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/plat_cfg
export PLAT_COMMON_DIR := $(PLATFORM_DIR)/common
ifneq ($(strip $(TARGET_BOARD_PLATFORM)), )
ifeq ($(LIBS_INSTALL_DIR),)
include $(BUILD_PACK)/plat_config.mk
endif
endif
include $(BUILD_CONFIG)/toolchain.mk
include $(BUILD_OPERATION)/project.mk

# for install header
ifeq ($(HDR_INSTALL_DIR),)
HDR_INSTALL_DIR:=$(HDR_L_DIR)
$(shell test -d $(HDR_INSTALL_DIR) || mkdir -p $(HDR_INSTALL_DIR))
endif

# default target
PHONY += libs $(drivers) $(frameworks) $(service) package
all: install_headers setup_links libs $(drivers) $(frameworks) $(service) package
tees: setup_links libs $(drivers) $(frameworks) $(service)
$(drivers): setup_links libs link_libs
$(frameworks): setup_links libs link_libs
$(service): setup_links libs link_libs
package: hmfilemgr

PHONY += link_libs link_arm_libs link_aarch64_libs
link_libs: link_arm_libs link_aarch64_libs
	mkdir -p $(OUTPUTDIR)/elfloader
	mkdir -p $(OUTPUTDIR)/kernel
	cp -a $(OUTPUTDIR)/$(TEE_ARCH)/libs/elfloader.o $(OUTPUTDIR)/elfloader/.
	cp -a $(OUTPUTDIR)/$(TEE_ARCH)/libs/kernel.elf $(OUTPUTDIR)/kernel/.
	cp -a $(OUTPUTDIR)/$(TEE_ARCH)/libs/libuart.a $(OUTPUTDIR)/kernel/.
	cp -a $(OUTPUTDIR)/$(TEE_ARCH)/libs/libhardware.a $(OUTPUTDIR)/kernel/.
	cp -a $(OUTPUTDIR)/$(TEE_ARCH)/libs/libklibc.a $(OUTPUTDIR)/kernel/.

link_arm_libs: libs
	@echo "[link] libs=$(libs)"
	$(VER) PBD=$(PREBUILD_LIBS)/arm/ ; \
	for lib in `ls $$PBD`; do \
		link=$(OUTPUTDIR)/arm/libs/$$lib ; \
		f=$$PBD/$$lib ; \
		if [ ! -L $$link ] && [ ! -e $$link ] ; then \
			ln -s $$f $$link && \
			echo "link prebuild library: $$link" ; \
		fi \
	done

link_aarch64_libs: libs
	@echo "[link] aarch libs=$(libs)"
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
	@echo "before tools ${EXPORT_HDRS}"
	$(VER) if [ -f "$(PLATFORM_DIR)/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg/plat_cfg.h" ] ; then \
	cp $(PLATFORM_DIR)/${PLATFORM_NAME}/${PRODUCT_NAME}/${CHIP_NAME}/plat_cfg/plat_cfg.h $(HDR_INSTALL_DIR)/; fi;
	touch $(HDR_INSTALL_DIR)/.timestamp

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
	$(MAKE) -C $(BUILD_TOOLS)/hmfilemgr ARCH=$(TEE_ARCH) -j

PHONY += teehm.img trustedcore.img
package: $(STAGE_DIR)/trustedcore.img
	@echo "!!generate trustedcore.img success"

PHONY += release
release:
	@echo "!!compile release"
	@rm -rf tools/elf_extract

PHONY += clean
clean: clean_links
	@rm -rf $(OUTPUTDIR)
	@rm -rf sec_trustedcore.img
	@rm -rf tools/linker.lds_pp
	@rm -rf $(TOPDIR)/prebuild
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
