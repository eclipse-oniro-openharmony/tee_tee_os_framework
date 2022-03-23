# platdrv compile rules
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.

inc-flags += -I$(SOURCE_DIR)/platform/ascend/include
# for sec
inc-flags += -I$(SOURCE_DIR)/platform/ascend/sec/include
API_CFILES = platform/ascend/sec/api/sec_api.c \
             platform/ascend/sec/api/sec.c
CFILES += $(API_CFILES)

# for trng
inc-flags += -I$(SOURCE_DIR)/platform/ascend/trng/include
APIT_CFILES = platform/ascend/trng/api/trng_api.c \
              platform/ascend/trng/api/trng.c
CFILES += $(APIT_CFILES)

# for sec hal
inc-flags += -I$(SOURCE_DIR)/platform/ascend/sec_hal/include
APIS_CFILES = $(TOPDIR)/libs/libplatdrv/platform/ascend/sec_hal/src/sec_hal.c
CFILES += $(APIS_CFILES)
# for oemkey
inc-flags += -I$(SOURCE_DIR)/platform/common/plat_cap
CFILES += platform/common/plat_cap/plat_cap_hal.c
# for scmi
inc-flags += -I$(SOURCE_DIR)/platform/ascend/hsm/scmi

CFILES += platform/ascend/hsm/scmi/scmi_api.c
CFILES += platform/ascend/hsm/scmi/scmi.c
# for sfc
inc-flags += -I$(SOURCE_DIR)/platform/ascend/sfc

CFILES += platform/ascend/sfc/sfc_api.c
CFILES += platform/ascend/sfc/sfc_driver.c

# for update firmware
inc-flags += -I$(SOURCE_DIR)/platform/ascend/hsm/hsm_update

CFILES += platform/ascend/hsm/hsm_update/hsm_update_api.c
CFILES += platform/ascend/hsm/hsm_update/hsm_dev_id.c
CFILES += platform/ascend/hsm/hsm_update/hsm_secure_rw.c

# for efuse
inc-flags += -I$(SOURCE_DIR)/platform/ascend/efuse

CFILES += platform/ascend/efuse/efuse_api.c
CFILES += platform/ascend/efuse/efuse.c

# for pg info get
inc-flags += -I$(SOURCE_DIR)/platform/ascend/hsm/hsm_pg_info
CFILES += platform/ascend/hsm/hsm_pg_info/hsm_pg_info_api.c

ifeq ($(CONFIG_HSM), true)
c-flags += -DTEE_SUPPORT_HSM
endif

ifeq ($(CONFIG_ASCEND_SEC_ENABLE), true)
c-flags += -DASCEND_SEC_ENABLE
endif
