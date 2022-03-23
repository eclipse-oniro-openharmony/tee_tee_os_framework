# TARGET is a TA app
TARGET := storage.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

storage_c_files += $(wildcard src/task_storage/*.c)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
storage_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
storage_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=

include $(TOPDIR)/mk/ta-common.mk
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
