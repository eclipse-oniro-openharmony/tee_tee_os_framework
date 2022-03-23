ifeq ($(CONFIG_ENABLE_XOM32),y)
ifeq (${TARG},_a32)
xom32-black-list := tui.elf libthp_afe_990.a
ifneq (${BUILD_TA},y)
ifneq (${TARGET_IS_TA},y)
ifeq ($(filter $(xom32-black-list),$(MODULE)), )
flags += -mexecute-only
flags += -fno-jump-tables
xom32_enable := y
ifeq ($(CONFIG_LLVM_CFI), y)
LD := $(LD-XOM)
endif
endif
else
ifeq (${TARGET_IS_EXT_LIB},y)
flags += -fno-jump-tables
xom32_enable := y
ifeq ($(CONFIG_LLVM_CFI), y)
LD := $(LD-XOM)
endif
else
ifeq ($(filter $(xom32-black-list),$(TARGET)), )
flags += -mexecute-only
flags += -fno-jump-tables
xom32_enable := y
ifeq ($(CONFIG_LLVM_CFI), y)
LD := $(LD-XOM)
endif
endif
endif
endif
endif
endif
endif
