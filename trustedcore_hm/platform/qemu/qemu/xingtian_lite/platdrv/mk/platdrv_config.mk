# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# qemu platdrv compile rules

inc-flags += -I$(SOURCE_DIR)/platform \
             -I$(SOURCE_DIR)/platform/common/include


ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
flags += -Iplatform/qemu/trngdriver_lib
CFILES += platform/qemu/trngdriver_lib/trng_api.c
CFILES += platform/qemu/qemu_hal.c
# oemkey
flags += -I$(SOURCE_DIR)/platform/common/plat_cap
CFILES += platform/qemu/plat_info.c
CFILES += platform/common/plat_cap/plat_cap_hal.c
endif
flags += -Wall -Wextra
