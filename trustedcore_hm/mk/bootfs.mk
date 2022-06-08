RAMFSMKIMG := $(PREBUILD_TOOLS)/ramfsmkimg
BOOTFS_INI := $(TOPDIR)/tools/bootfs.ini

# prebuild apps
ifeq ($(PERF_FUATURE), true)
boot-fs-files-y += $(PREBUILD_APPS)/perf
endif

ifeq ($(BENCHMARK), true)
boot-fs-files-y += $(PREBUILD_APPS)/benchmark_a32
endif

ifneq ($(CONFIG_SMCMGR_EMBEDDED), y)
boot-fs-files-y += $(PREBUILD_APPS)/teesmcmgr.elf
endif

ifeq ($(CONFIG_DYNLINK_TEST), y)
boot-fs-files-y += $(PREBUILD_LIBS)/arm/libtest_shared_a32.so
endif

# hm-apps, select by hm-apps config.mk
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

ifneq ($(CONFIG_NO_VENDOR_LIB_EMBEDDED), true)
    DEF_LIBVENDOR_SHARED := $(OUTPUTDIR)/arm/obj/arm/libvendor_shared/libvendor_shared_a32.so
    DEF_LIBVENDOR_SHARED_A64 := $(OUTPUTDIR)/aarch64/obj/aarch64/libvendor_shared/libvendor_shared.so
endif

$(STAGE_DIR)/bootfs.img: $(boot-fs-files-y) FORCE
	@if [ "xy" = "xy" ] ; then \
	set -e ;\
	for i in $(check-syms-y) ; do \
		echo " [ CHECK SYMS ]: $$i" ;\
		$(TOOLS)/check-syms.sh $$i \
			$(PREBUILD_LIBS)/arm/libc_shared_a32.so \
			$(OUTPUTDIR)/arm/obj/arm/libtee_shared/libtee_shared_a32.so \
			$(DEF_LIBVENDOR_SHARED) \
			$(OUTPUTDIR)/arm/obj/arm/libtui_internal_shared/libtui_internal_shared_a32.so \
			$(OUTPUTDIR)/arm/obj/arm/libdrv_shared/libdrv_shared_a32.so \
			$(OUTPUTDIR)/arm/obj/arm/libbase_shared/libbase_shared_a32.so; \
	done ;\
	for i in $(check-a64-syms-y) ; do \
		echo " [ CHECK a64 SYMS ]: $$i" ;\
		$(TOOLS)/check-syms.sh $$i \
			$(PREBUILD_LIBS)/aarch64/libc_shared.so \
			$(OUTPUTDIR)/aarch64/obj/aarch64/libtee_shared/libtee_shared.so \
			$(DEF_LIBVENDOR_SHARED_A64) \
			$(OUTPUTDIR)/aarch64/obj/aarch64/libtui_internal_shared/libtui_internal_shared.so \
			$(OUTPUTDIR)/aarch64/obj/aarch64/libdrv_shared/libdrv_shared.so \
			$(OUTPUTDIR)/aarch64/obj/aarch64/libbase_shared/libbase_shared.so; \
	done ; fi
	@test -d $(dir $@) || mkdir -p $(dir $@)
	@echo " [ MAKING BOOT RAMFS ]: $@"
	$(TOOLS)/smart-strip.sh $(boot-fs)
	$(VER) $(RAMFSMKIMG) -n $(HM_BOOTFS_SIZE) -f $(BOOTFS_INI) $@ $(boot-fs-files-y)

FORCE: ;
