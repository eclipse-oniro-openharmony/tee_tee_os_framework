ifeq ($(CONFIG_TUI_64BIT), true)
aarch64_frm_drivers += tui
product_apps += $(OUTPUTDIR)/aarch64/drivers/tui.elf
endif

ifeq ($(CONFIG_TUI_32BIT), true)
arm_sys_apps += tui
product_apps += $(OUTPUTDIR)/arm/apps/tui.elf
endif
