# cpio-strip compile rule.
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

override CC := gcc
GENERAL_OPTIONS := -Wall -Werror -Wextra -Wfloat-equal -Wshadow -Wtrampolines -Wformat=2\
                   -fno-common -fno-strict-aliasing -fsigned-char -pipe -fstack-protector-all
LINK_OPTIONS := -fPIC -Wl,-z,relro -Wl,-z,noexecstack -Wl,-z,now -pie -Wl,-Bsymbolic -rdynamic -Wl,--no-undefined

GCC_VERSION := $(shell expr `gcc -dumpversion | cut -f1 -d.` \>= 5)

ifeq ($(GCC_VERSION), 1)
GENERAL_OPTIONS += -Wdate-time
endif

#ifeq ($(CONFIG_HW_SECUREC_MIN_MEM),y)
GENERAL_OPTIONS += -DSECUREC_WARP_OUTPUT=1 -DSECUREC_WITH_PERFORMANCE_ADDONS=0
#endif
c_files := $(HM_APPS_DIR)/thirdparty/huawei/libhwsecurec/src/memcpy_s.c
c_files += $(HM_APPS_DIR)/thirdparty/huawei/libhwsecurec/src/memset_s.c
c_files += $(HM_APPS_DIR)/thirdparty/huawei/libhwsecurec/src/snprintf_s.c
c_files += $(HM_APPS_DIR)/thirdparty/huawei/libhwsecurec/src/vsnprintf_s.c
c_files += $(HM_APPS_DIR)/thirdparty/huawei/libhwsecurec/src/secureprintoutput_a.c

c_files_include += -I$(HM_APPS_DIR)/thirdparty/huawei/libhwsecurec/include/
c_files_include += -I$(HM_APPS_DIR)/thirdparty/huawei/libhwsecurec/include/libhwsecurec

cpio-strip : $(SOURCE_DIR)/cpio_strip.c $(LIBCPIO_BASE)/src/cpio.c $(LIBCPIO_BASE)/include/cpio/cpio.h
	@echo " [CC] $@"
	$(Q)$(CC) $(CPPFLAGS) $(GENERAL_OPTIONS) $(LINK_OPTIONS) -I$(LIBCPIO_BASE)/include $(c_files_include) $(c_files) $(filter %.c, $^) -o $@

