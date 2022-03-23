# hi5651t platdrv compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

# for hi5651 sec
inc-flags += -I$(SOURCE_DIR)/platform/lingxiao/sec/include
CFILES = platform/lingxiao/sec/src/hi_sec_drv.c \
		 platform/lingxiao/sec/src/hi_trng.c \
		 platform/lingxiao/sec/src/hi_kdf.c \
		 platform/lingxiao/sec/src/hi_sec_common.c \
		 platform/lingxiao/sec/src/sec_adapt.c \
		 platform/lingxiao/sec/src/sec_hal.c
