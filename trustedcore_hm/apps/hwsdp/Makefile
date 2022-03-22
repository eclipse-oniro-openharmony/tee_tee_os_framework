# TARGET is a TA app
TARGET := hwsdp.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

# Source files required to build the target
hwsdp_c_files += $(wildcard src/*.c)
inc-flags += -I$(APPS_DIR)/hwsdp/inc
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
hwsdp_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
hwsdp_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=
ifeq (${TARG},_a32)
flags += -DARM_PAE=1 -mfloat-abi=softfp -mfpu=neon
endif
ifeq (${TARG},)
flags += -DARM_PAE=1 -DCC_DRIVER=1
endif

include $(TOPDIR)/mk/ta-common.mk

flags += -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -Wstack-protector
flags += -fsigned-char -fno-common -fno-strict-aliasing -D_FORTIFY_SOURCE=2
flags += -fvisibility=hidden
