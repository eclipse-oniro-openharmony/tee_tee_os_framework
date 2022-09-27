# MODULE is a lib
# Targets

MODULE := libac_policy${TARG}.a
flags += -fno-builtin

inc-flags += -I$(TOPDIR)/sys_libs/libac_policy/include
inc-flags += -I$(TOPDIR)/sys_libs/libac_policy/src/
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/hm_policy
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/TEE_ext
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(PLATFORM_DIR)/common/include
inc-flags += -I$(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/tee_config
inc-flags += -I$(PLATFORM_DIR)/common/hm_policy

libac_policy_c_files += $(wildcard src/*.c)
libac_policy_c_files += $(PLATFORM_DIR)/$(PLATFORM_NAME)/$(PRODUCT_NAME)/common/hm_policy/policy.c

ifeq ($(CONFIG_HSM), true)
flags += -DTEE_SUPPORT_HSM
endif
# Header files/directories this library provides
EXPORT_HDRS := $(wildcard $(TOPDIR)/sys_libs/libac_policy/include/*)

include $(TOPDIR)/mk/lib-common.mk
include $(TOPDIR)/mk/feature-macro.mk
