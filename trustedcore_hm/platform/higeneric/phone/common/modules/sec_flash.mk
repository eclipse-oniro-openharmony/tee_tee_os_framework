arm_chip_apps += sec_flash
ifeq ($(CONFIG_DRV_64BIT),false)
product_apps += $(OUTPUTDIR)/arm/apps/sec_flash.elf
endif
ifeq ($(CONFIG_DRV_64BIT),true)
product_apps += $(OUTPUTDIR)/aarch64/apps/sec_flash.elf
endif
