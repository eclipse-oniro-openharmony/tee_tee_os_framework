/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: the data structures and macros definition for secure flash module
 * Author : security-bsp
 * Create : 2019/8/30
 */
#ifndef __SECUREFLASH_API_H__
#define __SECUREFLASH_API_H__
#include <stdint.h>
#include "tee_log.h"

#define SECFLASH_PRINT_ERROR(...)  tloge(__VA_ARGS__)
#ifdef SECFLASH_FACTORY_TEST_DEBUG_VERSION
#define SECFLASH_PRINT_INFO(...)   tloge(__VA_ARGS__)
#define SECFLASH_PRINT_DEBUG(...)  tloge(__VA_ARGS__)
#else
#define SECFLASH_PRINT_INFO(...)
#define SECFLASH_PRINT_DEBUG(...)
#endif

#define SECFLASH_KEY_LEN_IN_BITS  128
#define SECFLASH_KEY_LEN_IN_BYTES (SECFLASH_KEY_LEN_IN_BITS >> 3)
#define SECFLASH_KEY_LEN_IN_WORDS (SECFLASH_KEY_LEN_IN_BYTES / sizeof(uint32_t))

#define SECFLASH_IV_LEN_IN_BYTES    SECFLASH_KEY_LEN_IN_BYTES

#define SECFLASH_CONTEXT_LEN_IN_BYTES   16
#define SECFLASH_CONTEXT_START_IN_BYTES 14
#define SECFLASH_BINDING_COUNT_START_IN_BYTES 12

#define SECFLASH_LABLE_LEN_IN_BYTES       12
#define SECFLASH_KDF_MESSAGE_LEN_IN_BYTES 32

/* keyset_type definition */
#define SECFLASH_KVN_INITIAL_KEY1    0x30
#define SECFLASH_KVN_BINDING_KEY1    0x31
#define SECFLASH_KVN_INITIAL_KEY2    0x32
#define SECFLASH_KVN_BINDING_KEY2    0x33
#define SECFLASH_KVN_INITIAL_KEY3    0x34
#define SECFLASH_KVN_BINDING_KEY3    0x35
#define SECFLASH_KEYSET_TYPE_NUMBER  3
#define SECFLASH_KEYSET_SUBKEY_NUM   3
#define SECFLASH_SECURE_STORAGE_GROUP_SUBKEY_NUM   2

/* SECFLASH_KEY_LEN_IN_BYTES * SECFLASH_KEYSET_SUBKEY_NUM * SECFLASH_SECURE_STORAGE_GROUP_SUBKEY_NUM */
#define SECFLASH_INITKEY_SECURE_STORAGE_GROUP_MAX_BYTES  96

/* SECFLASH_KEY_LEN_IN_BYTES * SECFLASH_KEYSET_SUBKEY_NUM */
#define SECFLASH_INITKEY_MSP_CORE_GROUP_MAX_BYTES        48
#define SECFLASH_EFUSE_GROUP_BIT_SIZE    32

enum secflash_region_atrr_tag {
    HIGHREPAIR_OFF_FACTORYRECOVERY_OFF_TAG = 0,
    HIGHREPAIR_ON_FACTORYRECOVERY_OFF_TAG = 1,
    HIGHREPAIR_ON_FACTORYRECOVERY_ON_TAG = 2,
    MAXNUM_REGION_TAG
};

enum secflash_partition_name_type {
    SECFLASH_SYSTEM_TYPE = 0,
    SECFLASH_SECURE_STORAGE_TYPE = 1,
    SECFLASH_MAXNUM_TYPE
};

enum secflash_partition_state {
    PARTITION_INIT_COMPLETE_STATE = 0xDC0685AC,
    PARTITION_FACTORYRECOVERY_RUNNING_STATE = 0x8F354F4A,
    PARTITION_FACTORYRECOVERY_COMPLETE_STATE = 0x69422BE5,
};

/*
 * totoal 32 bytes, partition_magic_value equal to secflash_partition_state.
 */
struct secflash_partition_info {
    uint32_t partition_magic_value;
    uint32_t reserved[7];
};

/*
 * totoal 4 bytes, one block means 16bytes in secflash chip.
 */
struct secflash_region_attr_desc {
    uint16_t block_index;
    uint16_t block_size;
};

/*
 * totoal 32 bytes, one partition entry descriptor.
 */
struct secflash_partition_entry_desc {
    uint32_t module_id;
    struct secflash_region_attr_desc module_attr;
    struct secflash_region_attr_desc region_attr[MAXNUM_REGION_TAG];
    uint32_t reserved[3];
};

/*
 * totoal 512 bytes, the secflash partition table descriptor.
 * displit to one partition_info(32 bytes) and 15 partition entry(480 bytes).
 * Now only two entrys used: systerm and secure_storage.
 */
struct secflash_partition_table_desc {
    struct secflash_partition_info partition_info;
    struct secflash_partition_entry_desc partiton_entrys[15];
};


/*
 * secflash keyset type, contain secure storage and weaver, because they are handled independently.
 */
enum secflash_keyset_type {
    KEYSET_SECURE_STORAGE_TYPE = 0,
    KEYSET_WEAVER_TYPE = 1,
    KEYSET_MAXNUM_TYPE
};

/*
 * secflash keyset batch id, one byte.
 */
union secflash_batchid_desc {
    uint8_t value;
    struct {
        uint32_t batch_number:4;
        uint32_t debug_formal_flag:1;
        uint32_t keyset_version:3;
    } reg;
};

/*
 * secflash keyset vlaue, include 3 sub aes-key,used as enc,mac and dek Sequentially.
 */
struct secflash_keyset {
    uint8_t enc[SECFLASH_KEY_LEN_IN_BYTES];
    uint8_t mac[SECFLASH_KEY_LEN_IN_BYTES];
    uint8_t dek[SECFLASH_KEY_LEN_IN_BYTES];
};

uint32_t secflash_aes_cmac_wrapper(uint8_t *data_in_ptr, uint32_t data_size, uint8_t *derived_data);

#endif

