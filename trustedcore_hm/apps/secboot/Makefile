# TARGET is a TA app
TARGET := secboot.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

#secboot cfile here
secboot_c_files += $(wildcard src/*/*.c)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
secboot_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
secboot_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=

include $(TOPDIR)/mk/ta-common.mk


ifneq ($(filter $(TARGET_BOARD_PLATFORM),kirin980 orlando), )
flags += -DCONFIG_HISI_NVIM_SEC
flags += -DCONFIG_COLD_PATCH
endif

ifeq ($(TARGET_BOARD_PLATFORM),kirin990)
flags += -DCONFIG_HISI_NVIM_SEC
flags += -DCONFIG_COLD_PATCH
flags += -DCONFIG_MODEM_ASLR
endif
# will not compile secboot on virt. use kirin directly
inc-flags += -I$(LIBS_DIR)/libplatdrv/platform/libthirdparty_drv/plat_drv -I$(LIBS_DIR)/libplatdrv/platform/libthirdparty_drv/plat_drv/secureboot/include
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include # secboot_drv_call.h
inc-flags += -I$(TOPDIR)/vendor/common/include

DEP_LIBS :=
ifeq ($(TARGET_BOARD_PLATFORM),kirin980)
flags += -DCONFIG_MODEM_ASLR
endif
ifeq ($(TARGET_BOARD_PLATFORM),kirin710)
flags += -DCONFIG_COLD_PATCH
ifeq ($(with_rfdsp), true)
flags += -DCONFIG_RFIC_LOAD
endif
endif

ifeq ($(filter $(TARGET_BOARD_PLATFORM),kirin710 kirin970 kirin980 kirin990 orlando baltimore denver), )
flags += -DCONFIG_LOAD_MODEM_TEEOS
endif

flags_UNSUPPORTED += -Wno-unused-function
flags  += -Wdate-time
flags  += -Wextra
flags  += -Wfloat-equal
flags  += -Wformat=2
flags  += -Wshadow
DEP_LIBS += $(LIBCOMPILER_RT_BUILTINS)
secboot_LDFLAGS  += --start-group ${DEP_LIBS} --end-group
