# TARGET is a TA app
TARGET := attestation_ta.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

attestation_ta_c_files += $(wildcard src/task_attestation_ta/*.c)
ifeq ($(CONFIG_DYNLINK),y)
ifeq ($(CONFIG_GCOV), y)
attestation_ta_c_files += ../../sys_libs/libta_magic_a32/src/ta_magic.c
else
attestation_ta_c_files += $(TOPDIR)/sys_libs/libta_magic_a32/src/ta_magic.c
endif
endif

# c-flags += -I$(TOPDIR)/prebuild/hm-teeos-local-release/headers/hm_32/permission_service/
inc-flags += -I$(PLATFORM_DIR)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config

include $(TOPDIR)/mk/ta-common.mk
