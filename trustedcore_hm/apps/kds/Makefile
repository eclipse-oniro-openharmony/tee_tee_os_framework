# TARGET is a TA app
TARGET := kds.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

kds_c_files += $(wildcard src/*.c)
kds_c_files += $(wildcard src/task_kds/*.c)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
kds_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
kds_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=

flags += -DARM_PAE=1
include $(TOPDIR)/mk/ta-common.mk

inc-flags += -I$(TOPDIR)/vendor/common/include
flags += -Wdate-time -Wfloat-equal -Wshadow -Wformat=2 -Wstack-protector
flags += -fsigned-char -fno-common -fno-strict-aliasing -D_FORTIFY_SOURCE=2
flags += -fvisibility=hidden
