# Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.

# for hi3516 sec

inc-flags += -I$(SOURCE_DIR)/platform/ipc/sec/include
CFILES = platform/ipc/sec/cipher_syscall.c \
         platform/ipc/sec/src/cryp_trng.c \
         platform/ipc/sec/src/drv_trng.c \
         platform/ipc/sec/src/drv_klad.c \
         platform/ipc/sec/src/hal_otp.c \
         platform/ipc/sec/sec_hal.c \
         platform/ipc/sec/src/cipher_adapt.c

# for hi3516 oemkey
inc-flags += -I$(SOURCE_DIR)/platform/common/plat_cap
CFILES += platform/common/plat_cap/plat_cap_hal.c
