/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash interface implementation.
 * Author: l00265041
 * Create: 2019-09-15
 * Notes:
 * History: 2019-09-15 l00265041 create
 */

#ifndef __SECFLASH_INTERFACE_H__
#define __SECFLASH_INTERFACE_H__

#include <stdint.h>
#include "secureflash_errno.h"
#include "secureflash_api.h"
#include "tee_trusted_storage_api.h"

/* secure flash total region layout and common definitions */
#define SECFLASH_TOTAL_SIZE_IN_BYTES        (48 * 1024) /* 48Kbytes */
#define SECFLASH_BLOCK_LEN_IN_BYTES         16
#define SECFLASH_ONE_BLOCK_SIZE             1
#define SECFLASH_SIXTEEN_BLOCK_LEN_IN_BYTES 256
#define SECFLASH_SIXTEEN_BLOCK_SIZE         16
#define SECFLASH_PAGE_BLOCK_SIZE            64
#define SECFLASH_START_BLOCK_INDEX          0x0
#define SECFLASH_TOTAL_BLOCK_SIZE           (SECFLASH_TOTAL_SIZE_IN_BYTES / SECFLASH_BLOCK_LEN_IN_BYTES)

/* systerm partition layout */
#define SECFLASH_SYSTEM_START_BLOCK_INDEX  SECFLASH_START_BLOCK_INDEX
#define SECFLASH_SYSTEM_SIZE_IN_BYTES      (4 * 1024)
#define SECFLASH_SYSTEM_BLOCK_SIZE         (SECFLASH_SYSTEM_SIZE_IN_BYTES / SECFLASH_BLOCK_LEN_IN_BYTES)

/* 3 sub-region layout in systerm partition */
#define SYSTEM_REGION_0_START_BLOCK_INDEX   SECFLASH_SYSTEM_START_BLOCK_INDEX
#define SYSTEM_REGION_0_SIZE_IN_BYTES      (1 * 1024)
#define SYSTEM_REGION_0_BLOCK_SIZE         (SYSTEM_REGION_0_SIZE_IN_BYTES / SECFLASH_BLOCK_LEN_IN_BYTES)
#define SYSTEM_REGION_1_START_BLOCK_INDEX  (SYSTEM_REGION_0_START_BLOCK_INDEX + SYSTEM_REGION_0_BLOCK_SIZE)
#define SYSTEM_REGION_1_SIZE_IN_BYTES      (1 * 1024)
#define SYSTEM_REGION_1_BLOCK_SIZE         (SYSTEM_REGION_1_SIZE_IN_BYTES / SECFLASH_BLOCK_LEN_IN_BYTES)
#define SYSTEM_REGION_2_START_BLOCK_INDEX  (SYSTEM_REGION_1_START_BLOCK_INDEX + SYSTEM_REGION_1_BLOCK_SIZE)
#define SYSTEM_REGION_2_SIZE_IN_BYTES      (2 * 1024)
#define SYSTEM_REGION_2_BLOCK_SIZE         (SYSTEM_REGION_2_SIZE_IN_BYTES / SECFLASH_BLOCK_LEN_IN_BYTES)

/* secure storage partition layout */
#define SECFLASH_SECURE_STORAGE_START_BLOCK_INDEX  (SECFLASH_SYSTEM_START_BLOCK_INDEX + SECFLASH_SYSTEM_BLOCK_SIZE)
#define SECFLASH_SECURE_STORAGE_SIZE_IN_BYTES      (SECFLASH_TOTAL_SIZE_IN_BYTES - SECFLASH_SYSTEM_SIZE_IN_BYTES)
#define SECFLASH_SECURE_STORAGE_BLOCK_SIZE         (SECFLASH_SECURE_STORAGE_SIZE_IN_BYTES / SECFLASH_BLOCK_LEN_IN_BYTES)

/* partition table layout in systerm partition */
#define PARTITION_TABLE_TOTAL_SIZE_IN_BYTES 512
#define PARTITION_TABLE_HALF_SIZE_IN_BYTES  256
#define PARTITION_TABLE_START_BLOCK_INDEX   SECFLASH_START_BLOCK_INDEX
#define PARTITION_TABLE_TOTAL_BLOCK_SIZE    0x20
#define PARTITION_TABLE_HALF_BLOCK_SIZE     0x10
#define PARTITION_TABLE_MIDDLE_POSITION     0x7

#define PARTITION_TABLE_INFO_BLOCK_SIZE     0x2
#define PARTITION_TABLE_INFO_SIZE_IN_BYTES  32

/* writlock flag layout in systerm partition */
#define WRITELOCK_FLAG_BLOCK_INDEX (PARTITION_TABLE_START_BLOCK_INDEX + PARTITION_TABLE_TOTAL_BLOCK_SIZE)
#define WRITELOCK_FLAG_BLOCK_SIZE  0x1
#define WRITELOCK_FLAG_ENABLE      0xffffffff
#define WRITELOCK_FLAG_DISABLE     0x0


#define SF_BINDING_KEY_LEN_IN_BYTES  48
#define SECFLASH_IS_ABSENCE_MAGIC    0x70eb2c2d
#define SECFLASH_NXP_EXIST_MAGIC     0xa5c89cea
#define SECFLASH_ST_EXIST_MAGIC      0xe59a6b89
#define SECFLASH_RPMB_EXIST_MAGIC    0x5ea434a8

#define SECFLASH_FACTORY_TEST_MODULE   0x2de402e0
#define SECFLASH_SHAREMEM_READ_FLAG    0x9669A55A
#define SECFLASH_LOCAL_PART_TABLE_INIT_SUCCESS 0x17d1b5fa

enum caller_uuid_type {
    WEAVER_TA_CALLER = 0,
    HUAWEI_ANTITHEFT_TA_CALLER = 1,
    SECURE_STORAGE_TA_CALLER = 2,
    OTHER_CLASS_TA_CALLER = 3,
    MAX_NUM_TA_CALLER
};

struct secflash_dts_info {
    unsigned int fabricator_id;
    unsigned int chip_version;
    unsigned int total_size;
    unsigned int interface;
    unsigned int reset_gpio_num;
};

struct secflash_status_info {
	struct secflash_dts_info parsed_dts_value;
	unsigned int device_status;
	unsigned int device_efuse_counter;
	unsigned int reserved;
};

uint32_t secflash_device_is_available(uint32_t *status_info);
uint32_t secflash_get_device_efuse_count(uint32_t *efuse_count);
uint32_t secflash_factory_recovery(uint32_t flags);
uint32_t secflash_derive_binding_key(uint32_t keyset_type, uint32_t batch_id, struct secflash_keyset *binding_key);
uint32_t secflash_config_writelock_flag(bool is_set_operation, bool config_is_enable);
uint32_t secflash_get_phys_addr(uint32_t module_id, uint32_t block_index, uint32_t block_size, uint32_t *phys_block_index);
uint32_t secflash_set_region_info(uint32_t module_id, uint32_t tag_id, uint32_t block_index, uint32_t block_size);
uint32_t secflash_get_region_info(uint32_t module_id, uint32_t tag_id, uint32_t *block_index, uint32_t *block_size);
uint32_t secflash_set_partition_state(uint32_t partition_state);
uint32_t secflash_get_partition_state(uint32_t *partition_state);

void     secflash_ext_set_current_uuid(TEE_UUID *cur_uuid);
uint32_t secflash_ext_check_uuid(enum caller_uuid_type caller);
#endif /* __SECFLASH_INTERFACE_H__ */
