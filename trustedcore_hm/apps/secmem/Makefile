# TARGET is a TA app
TARGET := secmem.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

secmem_c_files += $(wildcard src/*.c)
secmem_c_files += $(wildcard src/task_secmem/*.c)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
secmem_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
secmem_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=

c-flags += -fno-common
c-flags += -Wall -Wextra
inc-flags += -I$(APPS_DIR)/secmem/src/task_secmem
inc-flags += -I$(TOPDIR)/drivers/platdrv/include # dynion.h
inc-flags += -I$(LIBS_DIR)/libvltmm_a32/include

include $(TOPDIR)/mk/ta-common.mk
