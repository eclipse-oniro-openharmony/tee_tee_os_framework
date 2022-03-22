# TARGET is a TA app
TARGET := secisp.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

secisp_c_files += $(wildcard $(TOPDIR)/apps/secisp/src/*.c)
secisp_c_files += $(wildcard $(TOPDIR)/apps/secisp/src/task_secisp/*.c)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
secisp_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
secisp_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# Libraries
LIBS :=
flags += -DTEE_SUPPORT_TZMP2
inc-flags += -I$(APPS_DIR)/secisp/src/task_secisp
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/TEE_ext/
inc-flags += -I$(TOPDIR)/drivers/platdrv/include # dynion.h
inc-flags += -I$(TOPDIR)/libs/libvltmm_a32/include

include $(TOPDIR)/mk/ta-common.mk
