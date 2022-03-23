ifeq ($(CONFIG_TUI_32BIT), true)
arm_pro_libs += libthp_afe_990
endif

ifeq ($(CONFIG_TUI_64BIT), true)
aarch64_arm_chip_libs += libthp_afe_990
endif
