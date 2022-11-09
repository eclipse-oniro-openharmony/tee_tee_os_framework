# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

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
c_files := $(TEE_SECUREC_DIR)/src/memcpy_s.c
c_files += $(TEE_SECUREC_DIR)/src/memset_s.c
c_files += $(TEE_SECUREC_DIR)/src/snprintf_s.c
c_files += $(TEE_SECUREC_DIR)/src/vsnprintf_s.c
c_files += $(TEE_SECUREC_DIR)/src/secureprintoutput_a.c

c_files_include += -I$(TEE_SECUREC_DIR)/include/

cpio-strip : $(SOURCE_DIR)/cpio_strip.c $(LIBCPIO_BASE)/src/cpio.c $(LIBCPIO_BASE)/include/cpio/cpio.h
	@echo " [CC] $@"
	$(Q)$(CC) $(CPPFLAGS) $(GENERAL_OPTIONS) $(LINK_OPTIONS) -I$(LIBCPIO_BASE)/include $(c_files_include) $(c_files) $(filter %.c, $^) -o $@

