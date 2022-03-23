ifeq ($(CONFIG_SE_SERVICE_64BIT), true)
product_apps += $(OUTPUTDIR)/aarch64/apps/se_service.elf
aarch64_frm_drivers += se_service
endif

ifeq ($(CONFIG_SE_SERVICE_32BIT), true)
arm_frm_drivers += se_service
product_apps += $(OUTPUTDIR)/arm/apps/se_service_a32/se_service.elf
$(OUTPUTDIR)/arm/apps/se_service_a32/se_service.elf:
	@mkdir $(OUTPUTDIR)/arm/apps/se_service_a32
	@cp $(OUTPUTDIR)/arm/apps/se_service_a32.elf $(OUTPUTDIR)/arm/apps/se_service_a32/se_service.elf
endif
