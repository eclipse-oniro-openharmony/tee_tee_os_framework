# TARGET is a TA app
TARGET := antiroot.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

antiroot_c_files += $(wildcard src/task_antiroot/*.c)
antiroot_c_files += src/task_antiroot/eima/eima_task.c
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
antiroot_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
antiroot_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

inc-flags += -I$(APPS_DIR)/antiroot/src/task_antiroot
inc-flags += -I$(APPS_DIR)/antiroot/src/task_antiroot/eima
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include # root_status_ops.h

# Libraries
LIBS :=

include $(TOPDIR)/mk/ta-common.mk

flags += -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -Wstack-protector
flags += -fsigned-char -fno-common -fno-strict-aliasing -D_FORTIFY_SOURCE=2
