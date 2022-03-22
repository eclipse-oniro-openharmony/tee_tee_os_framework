/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash interface implementation.
 * Author: l00265041
 * Create: 2019-09-16
 * Notes:
 * History: 2019-09-16 l00265041 create
 */
#include "secureflash_interface.h"
#include "secflash_scp03_comm.h"
#include "securec.h"
#include "tee_ext_api.h"
#include "tee_private_api.h"

/* all the UUID which can enjoy the secflash service.
 * g_uuid_white_list[0] is used for invalid UUID.
 */
#define HISI_UUID_WEAVER_TA \
{ \
    0x42abc5f0, \
    0x2d2e, \
    0x4c3d, \
    { \
        0x8c, 0x3f, 0x34, 0x99, 0x78, 0x3c, 0xa9, 0x73   \
    } \
}

#define HISI_UUID_HUAWEI_ANTITHEFT_TA \
{ \
    0xB4B71581, \
    0xADD2, \
    0xE89F, \
    { \
        0xD5, 0x36, 0xF3, 0x54, 0x36, 0xDC, 0x79, 0x73   \
    } \
}

#define UUID_SECURE_STORAGE_TA \
{ \
    0x6c8cf255, \
    0xca98, \
    0x439e, \
    { \
        0xa9, 0x8e, 0xad, 0xe6, 0x40, 0x22, 0xec, 0xb6   \
    } \
}

static const TEE_UUID g_uuid_weaver_white_list[] = {
    {0},
    HISI_UUID_WEAVER_TA  /* WEAVER_TA */
};

static const TEE_UUID g_uuid_antitheft_white_list[] = {
    {0},
    HISI_UUID_HUAWEI_ANTITHEFT_TA /* HUAWEI_ANTITHEFT_TA */
};

static const TEE_UUID g_uuid_secure_storage_white_list[] = {
    {0},
    UUID_SECURE_STORAGE_TA /* SECURE_STORAGE_TA */
};

static const TEE_UUID g_uuid_other_white_list[] = {
    {0},
    {0} /* OTHER_TA */
};

/*
 * local secure flash partition table stored in DDR currently,
 * avoiding to access secure flash device frequencely.
 * Pay attention to Synchronize with data in secure flash device.
 */
static struct secflash_partition_table_desc g_local_secflash_part_table;
static uint32_t g_local_part_table_init_flg = 0;

static struct secflash_status_info g_secflash_status = { {0}, 0, 0, 0 };
static uint32_t g_secflash_sharemem_read = 0;

/* The first element in g_uuid_white_list has not been used. */
#define WHITE_LIST_INVALID_INDEX      0
/* Valid index range of g_uuid_white_list. */
#define WHITE_LIST_VALID_INDEX_START  1
#define WHITE_LIST_VALID_INDEX_END(list) ((sizeof(list) /\
    sizeof(TEE_UUID)) - 1)

/* Point to the current TEE_UUID to be checked by g_uuid_white_list. */
static TEE_UUID *g_current_uuid = NULL;

/*
 * @brief      : clear the local partition table init flag to 0, indicating it need to init again
 * @return     : NA
 */
static void secflash_clear_part_table_init_flg(void)
{
    g_local_part_table_init_flg = 0;
}

/*
 * @brief      : set the local partition table init flag to magic value, indicating it has been init succelly
 * @return     : NA
 */
static void secflash_set_part_table_init_flg(void)
{
    g_local_part_table_init_flg = SECFLASH_LOCAL_PART_TABLE_INIT_SUCCESS;
}

/*
 * @brief      : get the local partition table init flag
 * @return     : uint32_t value
 */
static uint32_t secflash_get_part_table_init_flg(void)
{
	return g_local_part_table_init_flg;
}

/*
 * @brief     : Set the current TEE_UUID.
 * @param[in] : cur_uuid, The current TEE_UUID.
 * @param[out]: void
 * @return    : void
 */
void secflash_ext_set_current_uuid(TEE_UUID *cur_uuid)
{
    g_current_uuid = cur_uuid;
}

/*
 * @brief     : Check if the uuid is in white list.
 * @param[in] : caller, The uuid caller type to be checked.
 * @return    : Operation status: success(0) or other failure status.
 */
uint32_t secflash_ext_check_uuid(enum caller_uuid_type caller)
{
    const TEE_UUID *uuid_list_ptr = NULL;
    int start, end;

    if (!g_current_uuid) {
        SECFLASH_PRINT_ERROR("%s, null TEE_UUID access\n", __func__);
        return SECURE_FLASH_RET_ERR_1;
    }
    if (caller >= MAX_NUM_TA_CALLER) {
        SECFLASH_PRINT_ERROR("%s, invalid uuid_type:%d.\n", __func__, caller);
        return SECURE_FLASH_RET_ERR_2;
    }
    switch (caller) {
    case WEAVER_TA_CALLER:
        uuid_list_ptr = g_uuid_weaver_white_list;
        end = WHITE_LIST_VALID_INDEX_END(g_uuid_weaver_white_list);
        break;
    case HUAWEI_ANTITHEFT_TA_CALLER:
        uuid_list_ptr = g_uuid_antitheft_white_list;
        end = WHITE_LIST_VALID_INDEX_END(g_uuid_antitheft_white_list);
        break;
    case SECURE_STORAGE_TA_CALLER:
        uuid_list_ptr = g_uuid_secure_storage_white_list;
        end = WHITE_LIST_VALID_INDEX_END(g_uuid_secure_storage_white_list);
        break;
    case OTHER_CLASS_TA_CALLER:
        uuid_list_ptr = g_uuid_other_white_list;
        end = WHITE_LIST_VALID_INDEX_END(g_uuid_other_white_list);
        break;
    default:
        end = 0;
        break;
    }

    start = WHITE_LIST_VALID_INDEX_START;
    for (; start <= end; start++) {
        if (memcmp((uint8_t *)&uuid_list_ptr[start], (uint8_t *)g_current_uuid,
            sizeof(TEE_UUID)) == 0) {
            break;
        }
    }
    if (start > end) {
        SECFLASH_PRINT_ERROR("%s, uuid check failed\n", __func__);
        return SECURE_FLASH_RET_ERR_3;
    }
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : read the partition table data
 * @param[in]  : partition_table: the current partition table in secure flash
 * @return     : TRUE -- the partition table validation return OK
 *               FALSE -- the partition table validation return NOK
 */
static uint32_t secflash_read_partition_table(struct secflash_partition_table_desc *partition_table)
{
    uint8_t *part_table_ptr = NULL;
    uint32_t ret;

    if (!partition_table) {
        SECFLASH_PRINT_ERROR("%s partition_table is NULL.\n", __func__);
        return SECURE_FLASH_RET_ERR_1;
    }

    /* low part, total 256bytes, using 16 block access */
    part_table_ptr = (uint8_t *)&partition_table->partition_info;
    ret = secflash_read_blocks(SECFLASH_FACTORY_TEST_MODULE,
                    PARTITION_TABLE_START_BLOCK_INDEX,
                    PARTITION_TABLE_HALF_BLOCK_SIZE, part_table_ptr,
                    PARTITION_TABLE_HALF_SIZE_IN_BYTES);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_read_blocks low part failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }
    /* high part, total 256bytes, using 16 block access */
#ifdef SECFLASH_PARTITION_HIGH_HALF_ENABLE
    part_table_ptr = (uint8_t *)&partition_table->partiton_entrys[PARTITION_TABLE_MIDDLE_POSITION];
    ret = secflash_read_blocks(SECFLASH_FACTORY_TEST_MODULE,
                    PARTITION_TABLE_START_BLOCK_INDEX + PARTITION_TABLE_HALF_BLOCK_SIZE,
                    PARTITION_TABLE_HALF_BLOCK_SIZE, part_table_ptr,
                    PARTITION_TABLE_HALF_SIZE_IN_BYTES);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_read_blocks high part failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
    }
#endif
    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : write the partition table data
 * @param[in]  : partition_table: the current partition table in secure flash
 * @return     : TRUE -- the partition table validation return OK
 *               FALSE -- the partition table validation return NOK
 */
static uint32_t secflash_write_partition_table(const struct secflash_partition_table_desc *partition_table)
{
    uint8_t *part_table_ptr = NULL;
    uint32_t ret;

    if (!partition_table) {
        SECFLASH_PRINT_ERROR("%s partition_table is NULL.\n", __func__);
        return SECURE_FLASH_RET_ERR_1;
    }

    /* high part, total 256bytes */
#ifdef SECFLASH_PARTITION_HIGH_HALF_ENABLE
    part_table_ptr = (uint8_t *)&partition_table->partiton_entrys[PARTITION_TABLE_MIDDLE_POSITION];
    ret = secflash_write_blocks(SECFLASH_FACTORY_TEST_MODULE,
                    PARTITION_TABLE_START_BLOCK_INDEX + PARTITION_TABLE_HALF_BLOCK_SIZE,
                    PARTITION_TABLE_HALF_BLOCK_SIZE, part_table_ptr);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_write_blocks high part failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }
#endif
    /* low part, total 256bytes */
    part_table_ptr = (uint8_t *)&partition_table->partition_info;
    ret = secflash_write_blocks(SECFLASH_FACTORY_TEST_MODULE,
                    PARTITION_TABLE_START_BLOCK_INDEX,
                    PARTITION_TABLE_HALF_BLOCK_SIZE, part_table_ptr);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_write_blocks low part failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
    }
    /*
     * clear local parttion table init flg, indicating local partition table need sync
     * with data in secureflash forcely.
     */
    secflash_clear_part_table_init_flg();

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : get the local partition table pointer
 * @return     : NULL or pointer to g_local_secflash_part_table
 */
static void* secflash_get_local_part_table_ptr(void)
{
    uint32_t flags;
    uint32_t ret;

    flags = secflash_get_part_table_init_flg();
    if (flags != SECFLASH_LOCAL_PART_TABLE_INIT_SUCCESS) {
        SECFLASH_PRINT_INFO("%s part table is not init.\n", __func__);
        ret = secflash_read_partition_table(&g_local_secflash_part_table);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s secflash_read_partition_table failed(0x%x).\n", __func__, ret);
            return NULL;
        }
        secflash_set_part_table_init_flg();
    }
    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return (void *)&g_local_secflash_part_table;
}

/*
 * @brief      : do the partition table validation
 * @param[in]  : partition_table: the current partition table in secure flash
 * @return     : true -- the partition table validation return OK
 *               false -- the partition table validation return NOK
 */
static bool secflash_verify_partition_table(const struct secflash_partition_table_desc *partition_table)
{
    uint32_t partition_state;
    struct secflash_region_attr_desc curr_region_attr = {0, 0};
    const struct secflash_partition_entry_desc *system_entry_ptr = NULL;

    if (!partition_table) {
        SECFLASH_PRINT_ERROR("%s partition_table is NULL.\n", __func__);
        return false;
    }
    partition_state = partition_table->partition_info.partition_magic_value;
    if (partition_state != PARTITION_INIT_COMPLETE_STATE &&
        partition_state != PARTITION_FACTORYRECOVERY_RUNNING_STATE &&
        partition_state != PARTITION_FACTORYRECOVERY_COMPLETE_STATE) {
        SECFLASH_PRINT_ERROR("%s partition_state(0x%x) is invalid.\n", __func__, partition_state);
        return false;
    }
    system_entry_ptr = &partition_table->partiton_entrys[SECFLASH_SYSTEM_TYPE];
    if (system_entry_ptr->module_id != SECFLASH_SYSTEM_TYPE ||
        partition_table->partiton_entrys[SECFLASH_SECURE_STORAGE_TYPE].module_id != SECFLASH_SECURE_STORAGE_TYPE) {
        SECFLASH_PRINT_ERROR("%s module_id is invalid.\n", __func__);
        return false;
    }
    curr_region_attr = system_entry_ptr->module_attr;
    if (!(curr_region_attr.block_index == SECFLASH_SYSTEM_START_BLOCK_INDEX &&
          curr_region_attr.block_size == SECFLASH_SYSTEM_BLOCK_SIZE)) {
        SECFLASH_PRINT_ERROR("%s system partition is invalid.\n", __func__);
        return false;
    }

    curr_region_attr = system_entry_ptr->region_attr[HIGHREPAIR_OFF_FACTORYRECOVERY_OFF_TAG];
    if (!(curr_region_attr.block_index == SYSTEM_REGION_0_START_BLOCK_INDEX &&
          curr_region_attr.block_size == SYSTEM_REGION_0_BLOCK_SIZE)) {
        SECFLASH_PRINT_ERROR("%s system partition tag0 is invalid.\n", __func__);
        return false;
    }

    curr_region_attr = system_entry_ptr->region_attr[HIGHREPAIR_ON_FACTORYRECOVERY_OFF_TAG];
    if (!(curr_region_attr.block_index == SYSTEM_REGION_1_START_BLOCK_INDEX &&
          curr_region_attr.block_size == SYSTEM_REGION_1_BLOCK_SIZE)) {
        SECFLASH_PRINT_ERROR("%s system partition tag1 is invalid.\n", __func__);
        return false;
    }

    curr_region_attr = system_entry_ptr->region_attr[HIGHREPAIR_ON_FACTORYRECOVERY_ON_TAG];
    if (!(curr_region_attr.block_index == SYSTEM_REGION_2_BLOCK_SIZE &&
          curr_region_attr.block_size == SYSTEM_REGION_2_BLOCK_SIZE)) {
        SECFLASH_PRINT_ERROR("%s system partition tag2 is invalid.\n", __func__);
        return false;
    }

    curr_region_attr = partition_table->partiton_entrys[SECFLASH_SECURE_STORAGE_TYPE].module_attr;
    if (!(curr_region_attr.block_index == SECFLASH_SECURE_STORAGE_START_BLOCK_INDEX &&
          curr_region_attr.block_size == SECFLASH_SECURE_STORAGE_BLOCK_SIZE)) {
        SECFLASH_PRINT_ERROR("%s secure_storage partition is invalid.\n", __func__);
        return false;
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return true;
}

/*
 * @brief      : do the permission check for a given partition
 * @param[in]  : module_id: the module id, support secflash_partition_name_type and SECFLASH_FACTORY_TEST_MODULE
 *               block_index: the virtual block index
 *               block_size: the virtual block size
 *               partition_table: the current partition table in secure flash
 * @return     : true -- the permission check for partiton is pass
 *               false -- the permission check for partiton is NOT pass
 */
static bool secflash_partition_permission_check(uint32_t module_id, uint32_t block_index, uint32_t block_size,
                                                const struct secflash_partition_table_desc *partition_table)
{
    struct secflash_region_attr_desc curr_region_attr = {0, 0};

    if (module_id == SECFLASH_FACTORY_TEST_MODULE) {
        return true;
    }
    if (secflash_verify_partition_table(partition_table) == false) {
        SECFLASH_PRINT_ERROR("%s partition table verify failed.\n", __func__);
        return false;
    }

    curr_region_attr = partition_table->partiton_entrys[module_id].module_attr;
    if (block_index >= curr_region_attr.block_size || block_size > curr_region_attr.block_size ||
        (block_index + block_size) > curr_region_attr.block_size) { /* can't overflow when adding */
        SECFLASH_PRINT_ERROR("%s invalid block attr(0x%x,0x%x).\n", __func__, block_index, block_size);
        return false;
    }

    SECFLASH_PRINT_INFO("%s (0x%x 0x%x 0x%x)success.\n", __func__, module_id, block_index, block_size);
    return true;
}

/*
 * @brief      : get the real physical block index in secure flash device from virtual block index,according to a
 *               partition table, which maintained in system region
 * @param[in]  : module_id: the module id, support secflash_partition_name_type and SECFLASH_FACTORY_TEST_MODULE
 *               block_index: the virtual block index
 *               block_size: the virtual block size
 * @param[out] : phys_block_index: the real physical block index
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_get_phys_addr(uint32_t module_id, uint32_t block_index,
                                uint32_t block_size, uint32_t *phys_block_index)
{
    uint32_t max_module_block_size = SECFLASH_SYSTEM_BLOCK_SIZE;
    struct secflash_region_attr_desc curr_region_attr = { 0, 0 };
    struct secflash_partition_table_desc *partition_table_buff = NULL;

    if (module_id >= SECFLASH_MAXNUM_TYPE && module_id != SECFLASH_FACTORY_TEST_MODULE) {
        SECFLASH_PRINT_ERROR("%s invalid module_id(0x%x).\n", __func__, module_id);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    if (!phys_block_index) {
        SECFLASH_PRINT_ERROR("%s invalid phys_block_index=NULL.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }

    switch (module_id) {
    case SECFLASH_FACTORY_TEST_MODULE:
        max_module_block_size = SECFLASH_TOTAL_BLOCK_SIZE;
        break;
    case SECFLASH_SYSTEM_TYPE:
        max_module_block_size = SECFLASH_SYSTEM_BLOCK_SIZE;
        break;
    case SECFLASH_SECURE_STORAGE_TYPE:
        max_module_block_size = SECFLASH_SECURE_STORAGE_BLOCK_SIZE;
        break;
    default:
        break;
    }

    /* block_inde, block_size validation check, if failure return error */
    if (block_index >= max_module_block_size ||
        block_size > max_module_block_size ||
        (block_index + block_size) > max_module_block_size) { /* can't overflow when adding */
        SECFLASH_PRINT_ERROR("%s invalid block attr(0x%x,0x%x).\n", __func__, block_index, block_size);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
    }

    if (module_id == SECFLASH_FACTORY_TEST_MODULE) {
        *phys_block_index = block_index;
        SECFLASH_PRINT_ERROR("%s linely success.\n", __func__);
        return SECURE_FLASH_RET_SUCC;
    }

    partition_table_buff = secflash_get_local_part_table_ptr();
    if (!partition_table_buff) {
        SECFLASH_PRINT_ERROR("%s secflash_get_local_part_table_ptr failed.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_4);
    }
    if (secflash_partition_permission_check(module_id, block_index, block_size, partition_table_buff) == false) {
        SECFLASH_PRINT_ERROR("%s partition_permission_check failed.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_5);
    }

    curr_region_attr = partition_table_buff->partiton_entrys[module_id].module_attr;
    *phys_block_index = curr_region_attr.block_index + block_index;

    SECFLASH_PRINT_INFO("%s map success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : set the logical block_index and block_size to region info in partition table entry,according to a
 *               partition table and tag_id,which maintained in secure flash
 * @param[in]  : module_id: the module id, support secflash_partition_name_type and SECFLASH_FACTORY_TEST_MODULE
 *               tag_id: the region attribution id, support HIGHREPAIR_OFF_FACTORYRECOVERY_OFF_TAG,
 *                       HIGHREPAIR_ON_FACTORYRECOVERY_OFF_TAG and HIGHREPAIR_ON_FACTORYRECOVERY_ON_TAG.
 *               block_index: the logical block index in region,starting from a partition name.
 *               block_size: the logical block size in region,starting from a partition name
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_set_region_info(uint32_t module_id, uint32_t tag_id, uint32_t block_index, uint32_t block_size)
{
    uint32_t ret;
    struct secflash_partition_table_desc *partition_table_buff = NULL;
    struct secflash_region_attr_desc curr_region_attr = { 0, 0 };
    struct secflash_region_attr_desc *tag_region_attr_ptr = NULL;

    if (module_id >= SECFLASH_MAXNUM_TYPE) {
        SECFLASH_PRINT_ERROR("%s invalid module_id(0x%x).\n", __func__, module_id);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    if (tag_id >= MAXNUM_REGION_TAG) {
        SECFLASH_PRINT_ERROR("%s invalid tag_id(0x%x).\n", __func__, tag_id);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }

    partition_table_buff = secflash_get_local_part_table_ptr();
    if (!partition_table_buff) {
        SECFLASH_PRINT_ERROR("%s secflash_get_local_part_table_ptr failed.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
    }
    if (secflash_partition_permission_check(module_id, block_index, block_size, partition_table_buff) == false) {
        SECFLASH_PRINT_ERROR("%s partition_permission_check failed.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_4);
    }

    /* check the input region block_index and block_size(logical address) is valid or not */
    curr_region_attr = partition_table_buff->partiton_entrys[module_id].module_attr;
    if (block_index >= curr_region_attr.block_size || block_size > curr_region_attr.block_size  ||
        (block_index + block_size) > curr_region_attr.block_size) { /* can't overflow when adding */
        SECFLASH_PRINT_ERROR("%s invalid block attr(0x%x,0x%x).\n", __func__, block_index, block_size);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_5);
    }

    tag_region_attr_ptr = &(partition_table_buff->partiton_entrys[module_id].region_attr[tag_id]);
    /* process: update partition table to secure flash */
    tag_region_attr_ptr->block_index = block_index;
    tag_region_attr_ptr->block_size = block_size;
    ret = secflash_write_partition_table(partition_table_buff);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_write_partition_table failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_6);
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : get the logical block_index and block_size from region info in partition table entry,according to a
 *               partition table and tag_id,which maintained in secure flash
 * @param[in]  : module_id: the module id, support secflash_partition_name_type and SECFLASH_FACTORY_TEST_MODULE
 *               tag_id: the region attribution id, support HIGHREPAIR_OFF_FACTORYRECOVERY_OFF_TAG,
 *                       HIGHREPAIR_ON_FACTORYRECOVERY_OFF_TAG and HIGHREPAIR_ON_FACTORYRECOVERY_ON_TAG.
 * @param[out] : block_index: the logical block index in region indexed by tag_id
 *               block_size: the logical block size in region indexed by tag_id
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_get_region_info(uint32_t module_id, uint32_t tag_id, uint32_t *block_index, uint32_t *block_size)
{
    struct secflash_partition_table_desc *partition_table_buff = NULL;
    struct secflash_region_attr_desc *tag_region_attr_ptr = NULL;

    if (module_id >= SECFLASH_MAXNUM_TYPE) {
        SECFLASH_PRINT_ERROR("%s invalid module_id(0x%x).\n", __func__, module_id);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    if (tag_id >= MAXNUM_REGION_TAG) {
        SECFLASH_PRINT_ERROR("%s invalid tag_id(0x%x).\n", __func__, tag_id);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }
    if (!block_index || !block_size) {
        SECFLASH_PRINT_ERROR("%s the pointer parms is NULL\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
    }

    partition_table_buff = secflash_get_local_part_table_ptr();
    if (!partition_table_buff) {
        SECFLASH_PRINT_ERROR("%s secflash_get_local_part_table_ptr failed.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_4);
    }
    if (secflash_verify_partition_table(partition_table_buff) == false) {
        SECFLASH_PRINT_ERROR("%s partition_permission_check failed.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_5);
    }

    tag_region_attr_ptr = &(partition_table_buff->partiton_entrys[module_id].region_attr[tag_id]);
    *block_index = tag_region_attr_ptr->block_index;
    *block_size = tag_region_attr_ptr->block_size;

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}


/*
 * @brief      : set the secure flash partition operation state to partition table
 * @param[in]  : partition_state: the target partition operation state would be set to secure flash.
 *               PARTITION_INIT_COMPLETE_STATE,PARTITION_FACTORYRECOVERY_RUNNING_STATE and
 *               PARTITION_FACTORYRECOVERY_COMPLETE_STATE.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_set_partition_state(uint32_t partition_state)
{
    uint32_t ret;
    uint32_t curr_partition_state;
    struct secflash_partition_info curr_partition_info = {0};

    if (partition_state != PARTITION_INIT_COMPLETE_STATE &&
        partition_state != PARTITION_FACTORYRECOVERY_RUNNING_STATE &&
        partition_state != PARTITION_FACTORYRECOVERY_COMPLETE_STATE) {
        SECFLASH_PRINT_ERROR("%s invalid partition_state(0x%x).\n", __func__, partition_state);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    ret = secflash_read_blocks(SECFLASH_FACTORY_TEST_MODULE, PARTITION_TABLE_START_BLOCK_INDEX,
                   PARTITION_TABLE_INFO_BLOCK_SIZE,
                   (uint8_t *)&curr_partition_info, PARTITION_TABLE_INFO_SIZE_IN_BYTES);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s read partition info failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }
    curr_partition_state = curr_partition_info.partition_magic_value;
    if (partition_state == curr_partition_state) {
        SECFLASH_PRINT_ERROR("no need to config partition state(0x%x).\n", partition_state);
        return SECURE_FLASH_RET_SUCC;
    }

    curr_partition_info.partition_magic_value = partition_state;
    ret = secflash_write_blocks(SECFLASH_FACTORY_TEST_MODULE,
                    PARTITION_TABLE_START_BLOCK_INDEX,
                    PARTITION_TABLE_INFO_BLOCK_SIZE, (uint8_t *)&curr_partition_info);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s update partition info failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}


/*
 * @brief      : get the secure flash partition operation state to partition table
 * @param[out]  : partition_state: the target partition operation state from secure flash.
 *               PARTITION_INIT_COMPLETE_STATE,PARTITION_FACTORYRECOVERY_RUNNING_STATE and
 *               PARTITION_FACTORYRECOVERY_COMPLETE_STATE.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_get_partition_state(uint32_t *partition_state)
{
    uint32_t ret;
    struct secflash_partition_info curr_partition_info = {0};

    if (!partition_state) {
        SECFLASH_PRINT_ERROR("%s partition_state is NULL.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    ret = secflash_read_blocks(SECFLASH_FACTORY_TEST_MODULE, PARTITION_TABLE_START_BLOCK_INDEX,
                               PARTITION_TABLE_INFO_BLOCK_SIZE, (uint8_t *)&curr_partition_info,
                               PARTITION_TABLE_INFO_SIZE_IN_BYTES);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s read partition info failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }

    *partition_state = curr_partition_info.partition_magic_value;
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : secflash basic erase function
 * @param[in]  : partition_type: the partition type should be erased,
 *               tag_id: the tag id should be erased.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
static uint32_t secflash_basic_erase(enum secflash_partition_name_type partition_type,
                                     enum secflash_region_atrr_tag tag_id)
{
    uint32_t ret;
    uint32_t sixteen_block_count, i;
    uint8_t sixteen_block_data[SECFLASH_SIXTEEN_BLOCK_LEN_IN_BYTES] = {0};
    uint8_t one_block_data[SECFLASH_BLOCK_LEN_IN_BYTES] = {0};
    uint32_t block_index, block_size, block_size_remaining;

    ret = secflash_get_region_info(partition_type, tag_id, &block_index, &block_size);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_get_region_info failed(0x%x).\n", __func__, ret);
        return SECURE_FLASH_RET_ERR_1;
    }
    block_size_remaining = block_size;
    sixteen_block_count = 0;
    if (block_size >= SECFLASH_SIXTEEN_BLOCK_SIZE) {
        for (sixteen_block_count = 0; sixteen_block_count < block_size; ) {
            ret = secflash_write_blocks(partition_type,
                                        block_index + sixteen_block_count,
                                        SECFLASH_SIXTEEN_BLOCK_SIZE, sixteen_block_data);
            if (ret != SECURE_FLASH_RET_SUCC) {
                SECFLASH_PRINT_ERROR("%s secflash_write_blocks %d sixteen-blocks failed(0x%x).\n",
                                     __func__, sixteen_block_count, ret);
                return SECURE_FLASH_RET_ERR_2;
            }
            block_size_remaining -= SECFLASH_SIXTEEN_BLOCK_SIZE;
            sixteen_block_count += SECFLASH_SIXTEEN_BLOCK_SIZE;
            if (block_size_remaining < SECFLASH_SIXTEEN_BLOCK_SIZE) {
                break;
            }
        }
    }
    for (i = 0; i < block_size_remaining; i++) {
        ret = secflash_write_blocks(partition_type,
                                    block_index + sixteen_block_count + i,
                                    SECFLASH_ONE_BLOCK_SIZE, one_block_data);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s secflash_write_blocks %d one-block failed(0x%x).\n",
                                 __func__, i, ret);
            return SECURE_FLASH_RET_ERR_2;
        }
    }

    if (partition_type == SECFLASH_SECURE_STORAGE_TYPE) {
        ret = secflash_set_region_info(partition_type, tag_id, 0, 0);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s secflash_set_region_info %d %d failed(0x%x).\n",
                                 __func__, partition_type, tag_id, ret);
            return SECURE_FLASH_RET_ERR_3;
        }
    }
    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : secflash erase data process
 * @param[in]  : is_highrepair_erase: indicat whether the highrepair can erase,
 *               is_factoryrecovery_erase: indicat whether the factoryrecovery can erase.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
static uint32_t secflash_erase_data_process(bool is_highrepair_erase, bool is_factoryrecovery_erase)
{
    uint32_t ret;

    if (is_factoryrecovery_erase == true) {
        ret = secflash_basic_erase(SECFLASH_SYSTEM_TYPE, HIGHREPAIR_ON_FACTORYRECOVERY_ON_TAG);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s secflash_basic_erase part1 failed(0x%x).\n", __func__, ret);
            return SECURE_FLASH_RET_ERR_1;
        }
        ret = secflash_basic_erase(SECFLASH_SECURE_STORAGE_TYPE, HIGHREPAIR_ON_FACTORYRECOVERY_ON_TAG);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s secflash_basic_erase part2 failed(0x%x).\n", __func__, ret);
            return SECURE_FLASH_RET_ERR_2;
        }
    }
    if (is_highrepair_erase == true) {
        ret = secflash_basic_erase(SECFLASH_SYSTEM_TYPE, HIGHREPAIR_ON_FACTORYRECOVERY_OFF_TAG);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s secflash_basic_erase part3 failed(0x%x).\n", __func__, ret);
            return SECURE_FLASH_RET_ERR_3;
        }
        ret = secflash_basic_erase(SECFLASH_SECURE_STORAGE_TYPE, HIGHREPAIR_ON_FACTORYRECOVERY_OFF_TAG);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s secflash_basic_erase part4 failed(0x%x).\n", __func__, ret);
            return SECURE_FLASH_RET_ERR_4;
        }
    }
    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : get the secflash device status to g_secflash_status, include dts info and
 *               secflash devices whether is available.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
static uint32_t secflash_get_share_mem(void)
{
    uint32_t ret;

    if (g_secflash_sharemem_read != SECFLASH_SHAREMEM_READ_FLAG) {
        ret = TEE_EXT_GetSecFlashShareMem((char *)&g_secflash_status, sizeof(g_secflash_status));
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s TEE_EXT_GetSecFlashShareMem failed(0x%x).\n", __func__, ret);
            return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
        }
        g_secflash_sharemem_read = SECFLASH_SHAREMEM_READ_FLAG;
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : get the secflash device status, include dts info and secflash devices whether is available.
 * @param[out] : ptr_status_info: the pointer to a buffer, which type is struct secflash_status_info.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_get_device_status(struct secflash_status_info *ptr_status_info)
{
    uint32_t ret;
    uint32_t device_status;

    if (!ptr_status_info) {
        SECFLASH_PRINT_ERROR("%s ptr_status_info is NULL\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    ret = secflash_get_share_mem();
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_get_share_mem failed(0x%x)\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }
    device_status = g_secflash_status.device_status;
    if (device_status != SECFLASH_IS_ABSENCE_MAGIC && device_status != SECFLASH_NXP_EXIST_MAGIC &&
        device_status != SECFLASH_ST_EXIST_MAGIC) {
        SECFLASH_PRINT_ERROR("%s device_status(0x%x) invalid.\n", __func__, device_status);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
    }
    ret = memcpy_s((void *)ptr_status_info, sizeof(g_secflash_status),
            (void *)&g_secflash_status, sizeof(g_secflash_status));
    if (ret != EOK) {
        SECFLASH_PRINT_ERROR("%s memcpy_s failed(0x%x)\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_4);
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : judge the secflash device whether is exist, indicating NXP and ST device independly.
 * @param[out] : status_info: the pointer to a buffer, which type is a status variable.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_device_is_available(uint32_t *status_info)
{
    struct secflash_status_info device_status_info = { {0}, 0, 0, 0 };
    uint32_t ret;

    if (!status_info) {
        SECFLASH_PRINT_ERROR("%s status_info is NULL\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    ret = secflash_get_device_status(&device_status_info);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_get_device_status failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }
    *status_info = device_status_info.device_status;
    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : get the efuse count in efuse about secure flash device.
 * @param[out] : efuse_count: the pointer to a buffer, which type is a efuse count.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_get_device_efuse_count(uint32_t *efuse_count)
{
    struct secflash_status_info device_status_info = { {0}, 0, 0, 0 };
    uint32_t ret;

    if (!efuse_count) {
        SECFLASH_PRINT_ERROR("%s efuse_count is NULL\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    ret = secflash_get_device_status(&device_status_info);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_get_device_status failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }

    *efuse_count = device_status_info.device_efuse_counter;
    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : according flags(memory type indicator,or module_id),do region erasation in secure flash device.
 * @param[out] : flags, The memory type,the default value is 0xffffffff.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_factory_recovery(uint32_t flags)
{
    uint32_t ret;

    (void)flags;
    ret = secflash_set_partition_state(PARTITION_FACTORYRECOVERY_RUNNING_STATE);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_set_partition_state1 failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_9);
    }

    ret = secflash_erase_data_process(false, true);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_erase_data_process failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(ret);
    }

    ret = secflash_set_partition_state(PARTITION_FACTORYRECOVERY_COMPLETE_STATE);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_set_partition_state2 failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_10);
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : the writelock flag addr is first 4bytes which block_index is 0x20,
 *               Subsequently with the partition table. write the writelock flag to 0xffffffff(enable) or 0x0(disable).
 * @param[in]  : is_set_operation: true:set operation; false:get operation.
 * @param[in]  : config_is_enable: true means enable the writelock flag, false means disbale the writelock flag.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_config_writelock_flag(bool is_set_operation, bool config_is_enable)
{
    uint32_t ret;
    uint8_t block_data[SECFLASH_BLOCK_LEN_IN_BYTES] = {0};
    uint32_t *writelock_flg_ptr = NULL;
    uint32_t curr_writelock_flg;
    bool cfg_writelock_again = true;
    uint32_t device_status;

    ret = secflash_device_is_available(&device_status);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_device_is_available failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }

    if (device_status == SECFLASH_IS_ABSENCE_MAGIC) {
        SECFLASH_PRINT_ERROR("%s the secflash device is absence!\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_DEVICE_ABSENCE);
    }

    ret = secflash_read_blocks(SECFLASH_FACTORY_TEST_MODULE, WRITELOCK_FLAG_BLOCK_INDEX, WRITELOCK_FLAG_BLOCK_SIZE,
                               block_data, SECFLASH_BLOCK_LEN_IN_BYTES);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_read_blocks failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_2);
    }
    writelock_flg_ptr = (uint32_t *)block_data;
    curr_writelock_flg = *writelock_flg_ptr;
    if (is_set_operation == false) { /* get operation */
        if (curr_writelock_flg != WRITELOCK_FLAG_ENABLE) {
            SECFLASH_PRINT_ERROR("%s the writelock flag is not 0xffffffff.\n", __func__);
            return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_3);
        }
        return SECURE_FLASH_RET_SUCC;
    }

    if (config_is_enable && curr_writelock_flg != WRITELOCK_FLAG_ENABLE) {
        *writelock_flg_ptr = WRITELOCK_FLAG_ENABLE;
    } else if (!config_is_enable && curr_writelock_flg != WRITELOCK_FLAG_DISABLE) {
        *writelock_flg_ptr = WRITELOCK_FLAG_DISABLE;
    } else {
        SECFLASH_PRINT_ERROR("no need to config writelock flag(0x%x),is_enable %d.\n",
                             curr_writelock_flg, config_is_enable);
        cfg_writelock_again = false;
    }

    if (!cfg_writelock_again)
        return SECURE_FLASH_RET_SUCC;

    ret = secflash_write_blocks(SECFLASH_FACTORY_TEST_MODULE, WRITELOCK_FLAG_BLOCK_INDEX, WRITELOCK_FLAG_BLOCK_SIZE,
                                block_data);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_write_blocks failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_4);
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

