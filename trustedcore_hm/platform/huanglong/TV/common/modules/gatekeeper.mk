ifeq ($(CONFIG_GATEKEEPER_64BIT), true)
aarch64_sys_apps += gatekeeper
kirin_apps += $(OUTPUTDIR)/aarch64/apps/gatekeeper.elf
endif

ifeq ($(CONFIG_GATEKEEPER_32BIT), true)
arm_sys_apps += gatekeeper
kirin_apps += $(OUTPUTDIR)/arm/apps/gatekeeper.elf
endif


