# TARGET is a TA app
TARGET := gatekeeper.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

gatekeeper_c_files += $(wildcard src/task_gatekeeper/*.c)

ifeq (${TARG}, _a32)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
gatekeeper_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
gatekeeper_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif
endif

# Libraries
LIBS +=

flags += -DGATEKEEPER_ITRATION_TIMES=$(GATEKEEPER_ITRATION_TIMES)
flags += -DDERIVE_ROOT_INTERNAL_ITRATIONS=$(DERIVE_ROOT_INTERNAL_ITRATIONS)

inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include # gatekeeper_drv_call.h
inc-flags += -I$(TOPDIR)/vendor/higeneric/libpincode/include
inc-flags += -I$(TOPDIR)/sys_libs/libtee_shared/include

include $(TOPDIR)/mk/ta-common.mk
INCLUDE_PATH += $(DDK_INCLUDE_PATH_COMMON)
