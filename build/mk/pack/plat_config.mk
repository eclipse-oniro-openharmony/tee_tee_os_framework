include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/product_config.mk
include $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/$(CHIP_NAME)/chip.mk

ifeq ($(CONFIG_TA_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/drivers/tarunner.elf
endif

ifeq ($(CONFIG_HUK_SERVICE_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/apps/huk_service.elf
check-a64-syms-y += $(OUTPUTDIR)/aarch64/apps/huk_service.elf
endif
ifeq ($(CONFIG_HUK_SERVICE_32BIT), true)
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
endif

ifeq ($(CONFIG_TA_32BIT), true)
product_apps += $(OUTPUTDIR)/arm/obj/arm/libtee_shared/libtee_shared_a32.so
check-syms-y += $(OUTPUTDIR)/arm/obj/arm/libtee_shared/libtee_shared_a32.so
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
product_apps += $(OUTPUTDIR)/aarch64/drivers/tee_misc_driver.elf
check-syms-y += $(OUTPUTDIR)/aarch64/drivers/tee_misc_driver.elf
endif
endif
ifeq ($(CONFIG_DRVMGR_64BIT), false)
product_apps += $(OUTPUTDIR)/arm/drivers/drvmgr.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/drvmgr.elf
ifeq ($(CONFIG_TEE_MISC_DRIVER_64BIT), false)
product_apps += $(OUTPUTDIR)/arm/drivers/tee_misc_driver.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/tee_misc_driver.elf
endif
endif

ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/drivers/crypto_mgr.elf
check-a64-syms-y += $(OUTPUTDIR)/aarch64/drivers/crypto_mgr.elf
endif
ifeq ($(CONFIG_TEE_CRYPTO_MGR_SERVER_64BIT), false)
product_apps += $(OUTPUTDIR)/arm/drivers/crypto_mgr.elf
check-syms-y += $(OUTPUTDIR)/arm/drivers/crypto_mgr.elf
endif

