# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

# DRIVER is a driver

DRIVER := tarunner${TARG}.elf
SCRAMBLE_ME := $(CONFIG_SCRAMBLE_SYMS)

include $(TOPDIR)/mk/var.mk

tarunner_c_files := $(wildcard src/*.c)


# Libraries
LIBS := ta_mt${TARG} \
    c_shared${TARG}

inc-flags += -I$(TOPDIR)/sys_libs/libspawn_common/include/
inc-flags += -I$(TOPDIR)/sys_libs/libteeconfig/include/
inc-flags += -I$(TOPDIR)/sys_libs/libdrv_shared/src/
inc-flags += -I$(TOPDIR)/drivers/include

# drv makefile will fully link a binary.
include $(TOPDIR)/mk/svc-common.mk
tarunner_LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so -e main

ifeq (${CONFIG_ENABLE_XOM},y)
ifeq ($(ARCH),aarch64)
tarunner_LDFLAGS += -execute-only
endif
endif

ifeq ($(xom32_enable),y)
tarunner_LDFLAGS += -T $(XOM_LDS)
endif

ifneq (, $(filter $(TRUSTEDCORE_CHIP_CHOOSE), WITH_CHIP_HI1951 WITH_CHIP_HI1981))
tarunner_LDFLAGS += -E
endif
