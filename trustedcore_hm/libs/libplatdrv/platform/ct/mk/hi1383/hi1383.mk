# hi1383 platdrv compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
inc-flags += -I$(SOURCE_DIR)/platform/ct/trng

CFILES += platform/ct/trng/trng_api.c
CFILES += platform/ct/trng/trng_hal.c

flags += -Wall -Wextra
