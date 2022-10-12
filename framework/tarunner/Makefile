# Copyright Huawei Technologies Co., Ltd. 2010-2019. All rights reserved.

# DRIVER is a driver

DRIVER := tarunner${TARG}.elf

include $(TOPDIR)/mk/var.mk

tarunner_c_files := $(wildcard src/*.c)


# Libraries
LIBS := c_shared${TARG}

inc-flags += -I$(TOPDIR)/sys_libs/libspawn_common/include/
inc-flags += -I$(DRVLIB)/libdrv_shared/src/
inc-flags += -I$(TEELIB)/libteeconfig/include/
inc-flags += -I$(TEELIB)/libagent_base/include/
inc-flags += -I$(TEELIB)/libteeos/include/tee
inc-flags += -I$(TEELIB)/libteeos/include/legacy
inc-flags += -I$(TEELIB)/libteeos/include
inc-flags += -I$(DRIVERS_PATH)/include
inc-flags += -I$(TEELIB)/libteemem/include
inc-flags += -I$(PREBUILD_DIR)/sys/hmapi
inc-flags += -I$(FRAMEWORK_PATH)/gtask/src/framework

# drv makefile will fully link a binary.
include $(TOPDIR)/mk/svc-common.mk
tarunner_LDFLAGS += -z text -z noexecstack --dynamic-linker=libc_shared${TARG}.so -e main

ifneq (, $(filter $(TRUSTEDCORE_CHIP_CHOOSE), WITH_CHIP_TDA4 WITH_CHIP_HI1951 WITH_CHIP_HI1981 WITH_CHIP_HI1911))
tarunner_LDFLAGS += -E
endif
