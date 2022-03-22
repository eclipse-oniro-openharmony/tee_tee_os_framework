# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# hi1620 platdrv compile rules

inc-flags += -I$(SOURCE_DIR)/platform \
             -I$(SOURCE_DIR)/platform/common/include \
			 -I$(PREBUILD_HEADER)/sys/mmgr \
			 -I$(PREBUILD_HEADER)/sys/mmgr_sysmgr


ifeq ($(CONFIG_TRNG_ENABLE), true)
flags += -DTRNG_ENABLE
flags += -Iplatform/kunpeng/trngdriver_lib
flags += -Iplatform/kunpeng/acc_lib/include
CFILES += platform/kunpeng/sec_hal.c \
          platform/kunpeng/trngdriver_lib/trng_api.c
CFILES += platform/kunpeng/acc_lib/src/sec_api.c
CFILES += platform/kunpeng/acc_lib/src/hi_sec_dlv.c
CFILES += platform/kunpeng/acc_lib/src/acc_common.c
CFILES += platform/kunpeng/acc_lib/src/acc_common_sess.c
CFILES += platform/kunpeng/acc_lib/src/acc_common_drv.c
CFILES += platform/kunpeng/acc_lib/src/acc_common_qm.c
CFILES += platform/kunpeng/acc_lib/src/hi_sec_atest_api.c
CFILES += platform/kunpeng/acc_lib/src/acc_common_isr.c
endif

# secboot
CFILES += platform/kunpeng/secboot/secureboot.c
CFILES += platform/kunpeng/secboot/getcert.c

# oemkey
inc-flags += -I$(SOURCE_DIR)/platform/common/plat_cap
CFILES += platform/common/plat_cap/plat_cap_hal.c

flags += -Wall -Wextra
