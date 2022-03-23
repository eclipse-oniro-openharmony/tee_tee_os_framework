ifeq ($(CONFIG_KEYMASTER_64BIT), true)
aarch64_sys_apps += keymaster
product_apps += $(OUTPUTDIR)/aarch64/apps/keymaster.elf
endif
ifeq ($(CONFIG_KEYMASTER_32BIT), true)
arm_sys_apps += keymaster
product_apps += $(OUTPUTDIR)/arm/apps/keymaster.elf
endif

