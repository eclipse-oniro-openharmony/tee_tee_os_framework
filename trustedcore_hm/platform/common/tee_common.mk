#ta loader and gtask sysmgr core service packages of 64 bit runntime
#Compile libs for hm-apps

arm_libs +=
arm_sys_libs += libbase_shared
arm_drv_libs += libdrv_shared
arm_host_libs += libhwsecurec_host
arm_pro_libs +=
arm_chip_libs += ramfsmkimg_host
aarch64_libs += libac_policy
aarch64_drv_common_libs += libdrv_frame
aarch64_sys_libs += libdynconfmgr libdynconfbuilder
hm_kernel    := kernel
hm_elfloader := elfloader
#Compile ext_libs for hm-apps
arm_ext_libs +=
thirdparty_libs += libhwsecurec
host_tools +=

ifeq ($(CONFIG_CRYPTO_SOFT_ENGINE),mbedtls)
arm_open_source_libs +=
else
arm_open_source_libs +=
endif
arm_open_source_libs +=
aarch64_ext_libs +=
aarch64_open_source_libs +=

ifeq ($(CONFIG_ARCH_AARCH64),y)
aarch64_frm_drivers += hmsysmgr
else
arm_frm_drivers += hmsysmgr
endif

ifdef CONFIG_SSA_64BIT
ifeq ($(CONFIG_SSA_64BIT), true)
aarch64_services_drivers += ssa
else
arm_services_drivers += ssa
endif
endif

ifdef CONFIG_PERMSRV_64BIT
ifeq ($(CONFIG_PERMSRV_64BIT), true)
aarch64_services_drivers += permission_service
else
arm_services_drivers += permission_service
endif
endif

ifneq ($(CONFIG_OFF_DRV_TIMER), y)
ifeq ($(CONFIG_DRV_TIMER_64BIT), true)
aarch64_driver_drivers += drv_timer
endif
ifeq ($(CONFIG_DRV_TIMER_64BIT), false)
arm_driver_drivers += drv_timer
endif
endif

ifeq ($(CONFIG_TA_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/drivers/tarunner.elf
endif

ifeq ($(CONFIG_HUK_SERVICE_64BIT), true)
aarch64_services_drivers += huk_service
product_apps += $(OUTPUTDIR)/aarch64/apps/huk_service.elf
check-a64-syms-y += $(OUTPUTDIR)/aarch64/apps/huk_service.elf
endif
ifeq ($(CONFIG_HUK_SERVICE_32BIT), true)
arm_services_drivers += huk_service
product_apps += $(OUTPUTDIR)/arm/apps/huk_service_a32/huk_service.elf
check-syms-y += $(OUTPUTDIR)/arm/apps/huk_service_a32/huk_service.elf
$(OUTPUTDIR)/arm/apps/huk_service_a32/huk_service.elf:
	@mkdir $(OUTPUTDIR)/arm/apps/huk_service_a32
	@cp $(OUTPUTDIR)/arm/apps/huk_service_a32.elf $(OUTPUTDIR)/arm/apps/huk_service_a32/huk_service.elf
endif

ifdef CONFIG_SSA_64BIT
ifeq ($(CONFIG_SSA_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/drivers/ssa.elf
check-a64-syms-y += $(OUTPUTDIR)/aarch64/drivers/ssa.elf
else
product_apps += $(OUTPUTDIR)/arm/drivers/ssa_a32/ssa.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/ssa_a32/ssa.elf
$(OUTPUTDIR)/arm/drivers/ssa_a32/ssa.elf:
	 @mkdir $(OUTPUTDIR)/arm/drivers/ssa_a32
	 @cp $(OUTPUTDIR)/arm/drivers/ssa_a32.elf $(OUTPUTDIR)/arm/drivers/ssa_a32/ssa.elf
endif
endif

ifdef CONFIG_PERMSRV_64BIT
ifeq ($(CONFIG_PERMSRV_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/apps/permission_service.elf
else
product_apps += $(OUTPUTDIR)/arm/apps/permission_service_a32/permission_service.elf
$(OUTPUTDIR)/arm/apps/permission_service_a32/permission_service.elf:
	@mkdir $(OUTPUTDIR)/arm/apps/permission_service_a32
	@cp $(OUTPUTDIR)/arm/apps/permission_service_a32.elf $(OUTPUTDIR)/arm/apps/permission_service_a32/permission_service.elf
endif
endif

ifeq ($(CONFIG_TA_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/obj/aarch64/libtee_shared/libtee_shared.so
check-a64-syms-y += $(OUTPUTDIR)/aarch64/obj/aarch64/libtee_shared/libtee_shared.so
product_apps += $(OUTPUTDIR)/aarch64/obj/aarch64/libbase_shared/libbase_shared.so
check-a64-syms-y += $(OUTPUTDIR)/aarch64/obj/aarch64/libbase_shared/libbase_shared.so
endif

ifeq ($(CONFIG_TA_32BIT), true)
product_apps += $(OUTPUTDIR)/arm/obj/arm/libtee_shared/libtee_shared_a32.so
check-syms-y += $(OUTPUTDIR)/arm/obj/arm/libtee_shared/libtee_shared_a32.so
product_apps += $(OUTPUTDIR)/arm/obj/arm/libbase_shared/libbase_shared_a32.so
check-syms-y += $(OUTPUTDIR)/arm/obj/arm/libbase_shared/libbase_shared_a32.so
product_apps += $(OUTPUTDIR)/arm/drivers/tarunner_a32.elf
endif

ifeq ($(CONFIG_GTASK_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/drivers/gtask.elf
check-a64-syms-y +=  $(OUTPUTDIR)/aarch64/drivers/gtask.elf
else
product_apps += $(OUTPUTDIR)/arm/drivers/gtask.elf
check-syms-y +=  $(OUTPUTDIR)/arm/drivers/gtask.elf
$(OUTPUTDIR)/arm/drivers/gtask.elf:
	@cp $(OUTPUTDIR)/arm/drivers/gtask_a32.elf $(OUTPUTDIR)/arm/drivers/gtask.elf
endif

ifneq ($(CONFIG_OFF_DRV_TIMER), y)
ifeq ($(CONFIG_DRV_TIMER_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/drivers/drv_timer.elf
check-a64-syms-y += $(OUTPUTDIR)/aarch64/drivers/drv_timer.elf
endif
ifeq ($(CONFIG_DRV_TIMER_64BIT), false)
product_apps += $(OUTPUTDIR)/arm/drivers/drv_timer.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/drv_timer.elf
endif
endif

ifneq ($(CONFIG_PLATDRV_64BIT),)
ifeq ($(CONFIG_SUPPORT_64BIT),)
product_apps += $(OUTPUTDIR)/aarch64/obj/aarch64/libdrv_shared/libdrv_shared.so
product_apps += $(OUTPUTDIR)/arm/obj/arm/libdrv_shared/libdrv_shared_a32.so
else
ifeq ($(CONFIG_SUPPORT_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/obj/aarch64/libdrv_shared/libdrv_shared.so
endif
ifeq ($(CONFIG_SUPPORT_64BIT), false)
product_apps += $(OUTPUTDIR)/arm/obj/arm/libdrv_shared/libdrv_shared_a32.so
endif
endif
else
ifneq ($(CONFIG_DRVMGR_64BIT),)
ifeq ($(CONFIG_SUPPORT_64BIT),)
product_apps += $(OUTPUTDIR)/aarch64/obj/aarch64/libdrv_shared/libdrv_shared.so
product_apps += $(OUTPUTDIR)/arm/obj/arm/libdrv_shared/libdrv_shared_a32.so
else
ifeq ($(CONFIG_SUPPORT_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/obj/aarch64/libdrv_shared/libdrv_shared.so
endif
ifeq ($(CONFIG_SUPPORT_64BIT), false)
product_apps += $(OUTPUTDIR)/arm/obj/arm/libdrv_shared/libdrv_shared_a32.so
endif
endif
endif
endif

ifeq ($(CONFIG_DRVMGR_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/drivers/drvmgr.elf
check-syms-y += $(OUTPUTDIR)/aarch64/drivers/drvmgr.elf
ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), true)
aarch64_driver_drivers += tee_misc_driver
product_apps += $(OUTPUTDIR)/aarch64/drivers/tee_misc_driver.elf
check-syms-y += $(OUTPUTDIR)/aarch64/drivers/tee_misc_driver.elf
endif
endif
ifeq ($(CONFIG_DRVMGR_64BIT), false)
product_apps += $(OUTPUTDIR)/arm/drivers/drvmgr.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/drvmgr.elf
ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
arm_driver_drivers += tee_misc_driver
product_apps += $(OUTPUTDIR)/arm/drivers/tee_misc_driver.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/tee_misc_driver.elf
endif
endif

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
aarch64_driver_drivers += crypto_mgr
product_apps += $(OUTPUTDIR)/aarch64/drivers/crypto_mgr.elf
check-a64-syms-y += $(OUTPUTDIR)/aarch64/drivers/crypto_mgr.elf
endif
ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), false)
arm_driver_drivers += crypto_mgr
product_apps += $(OUTPUTDIR)/arm/drivers/crypto_mgr.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/crypto_mgr.elf
endif

ifeq ($(CONFIG_KMS), true)
aarch64_sys_apps += kms
product_apps += $(OUTPUTDIR)/aarch64/apps/kms.elf
endif

