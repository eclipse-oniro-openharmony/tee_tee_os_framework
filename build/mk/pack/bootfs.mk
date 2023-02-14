# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

RAMFSMKIMG := $(PREBUILD_TOOLS)/ramfsmkimg

# prebuild apps
ifeq ($(PERF_FUATURE), true)
boot-fs-files-y += $(PREBUILD_APPS)/perf
endif

ifeq ($(BENCHMARK), true)
boot-fs-files-y += $(PREBUILD_APPS)/benchmark_a32
endif

boot-fs-files-y += $(OUTPUTDIR)/arm/apps/teesmcmgr.elf

# tee framework, select by tee framework config.mk
# all products should define product_apps for themselves
boot-fs-files-y += $(product_apps)

ifneq ($(CONFIG_NOT_CHECK_SYM_A32), y)
check-syms-y += $(filter-out $(OUTPUTDIR)/arm/drivers/%.elf $(OUTPUTDIR)/aarch64/drivers/%.elf, $(product_apps))
endif

ifeq ($(CONFIG_TA_64BIT), true)
boot-fs-files-y += $(PREBUILD_LIBS)/aarch64/libc_shared.so
endif
ifeq ($(CONFIG_TA_32BIT), true)
boot-fs-files-y += $(PREBUILD_LIBS)/arm/libc_shared_a32.so
endif

boot-fs := $(boot-fs-files-y)
boot-fs := $(filter-out $(PREBUILD_LIBS)/aarch64/libc_shared.so $(PREBUILD_LIBS)/arm/libc_shared_a32.so, $(boot-fs))

$(STAGE_DIR)/bootfs.img: $(boot-fs-files-y) FORCE
	@if [ "xy" = "xy" ] ; then \
	set -e ;\
	for i in $(check-syms-y) ; do \
		echo " [ CHECK SYMS ]: $$i" ;\
		$(TOPDIR)/../tee_os_kernel/build/tools/generate_img/check-syms.sh $$i \
			$(PREBUILD_LIBS)/arm/libc_shared_a32.so \
			$(OUTPUTDIR)/arm/obj/arm/libtee_shared/libtee_shared_a32.so \
			$(OUTPUTDIR)/arm/obj/arm/libdrv_shared/libdrv_shared_a32.so; \
	done ;\
	for i in $(check-a64-syms-y) ; do \
		echo " [ CHECK a64 SYMS ]: $$i" ;\
		$(TOPDIR)/../tee_os_kernel/build/tools/generate_img/check-syms.sh $$i \
			$(PREBUILD_LIBS)/aarch64/libc_shared.so \
			$(OUTPUTDIR)/aarch64/obj/aarch64/libtee_shared/libtee_shared.so \
			$(OUTPUTDIR)/aarch64/obj/aarch64/libdrv_shared/libdrv_shared.so; \
	done ; fi
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo " [ MAKING BOOT RAMFS ]: $@"
	$(TOPDIR)/../tee_os_kernel/build/tools/generate_img/smart-strip.sh $(boot-fs)
	$(VER) $(RAMFSMKIMG) -n $(HM_BOOTFS_SIZE) $@ $(boot-fs-files-y)

FORCE: ;
