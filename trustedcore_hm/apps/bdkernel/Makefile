# TARGET is a TA app
TARGET := bdkernel.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

# Source files required to build the target
bdkernel_c_files += $(wildcard src/task_bdkernel/*.c)
#bdkernel_c_files += src/task_bdkernel/bdkernel_ta.c
inc-flags += -I$(APPS_DIR)/bdkernel/src/task_bdkernel
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
bdkernel_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
bdkernel_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
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
