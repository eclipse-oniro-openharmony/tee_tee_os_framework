# TARGET is a TA app
TARGET := sem.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

# Source files required to build the target
sem_c_files += $(wildcard src/*.c)
sem_c_files += $(wildcard src/task_sem/*.c)
sem_c_files += $(wildcard src/task_ukey/*.c)
sem_c_files += $(wildcard src/task_ukey/common/libs/src/*.c)
sem_c_files += $(wildcard src/task_ukey/common/rpmb_sfs_util/src/*.c)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
sem_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
sem_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=

inc-flags += -I$(APPS_DIR)/sem/src/task_ukey
inc-flags += -I$(APPS_DIR)/sem/src/task_ukey/common/libs/inc
inc-flags += -I$(APPS_DIR)/sem/src/task_ukey/common/rpmb_sfs_util/inc

include $(TOPDIR)/mk/ta-common.mk

flags += -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -Wstack-protector
flags += -fsigned-char -fno-common -fno-strict-aliasing -D_FORTIFY_SOURCE=2

