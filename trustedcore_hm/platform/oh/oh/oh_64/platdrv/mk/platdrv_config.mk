# Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.

inc-flags += -I$(SOURCE_DIR)/platform \
             -I$(SOURCE_DIR)/platform/common/include


ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
flags += -Iplatform/qemu/trngdriver_lib
CFILES += platform/qemu/trngdriver_lib/trng_api.c
CFILES += platform/qemu/qemu_hal.c
endif
flags += -Wall -Wextra
