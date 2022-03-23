/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash memory management.
 * Author: chengruhong
 * Create: 2019-08-27
 * Notes:
 * History: 2019-08-27 chengruhong create
 */
#include "secflash_mm.h"
#include "securec.h"
#include "secureflash_interface.h"
#include "secflash_scp03_comm.h"

/* 1 block == 16 byte */
#define BLOCK_SIZE 16
#define is_block_aligned(size) (((size) % BLOCK_SIZE) == 0)
#define block_to_byte(block) (BLOCK_SIZE * (block))
#define byte_to_block(size) ((size) / BLOCK_SIZE)

/* secflash total size and base info */
#define SECFLASH_BYTE_SIZE (44 * 1024)
#define SECFLASH_BLOCK_COUNT byte_to_block(SECFLASH_BYTE_SIZE)
#define SECFLASH_MEMORY_BASE 0
#define SECFLASH_MEMORY_END (SECFLASH_MEMORY_BASE + SECFLASH_BLOCK_COUNT)

/* size in block count of the secflash management data information */
#define SECFLASH_MNG_INFO_COUNT byte_to_block(2 * 1024)
#define SECFLASH_MNG_INFO_END SECFLASH_MEMORY_END
#define SECFLASH_MNG_INFO_BASE (SECFLASH_MNG_INFO_END - SECFLASH_MNG_INFO_COUNT)

/* secflash init flag zone, 1 block in the highest area of secflash */
#define SECFLASH_INIT_FLAG_COUNT 1
#define SECFLASH_INIT_FLAG_OFFSET (SECFLASH_MNG_INFO_END - SECFLASH_INIT_FLAG_COUNT)

/* secflash recovery information, 1 block below the init flag zone */
#define SECFLASH_RECOVERY_INFO_COUNT 1
#define SECFLASH_RECOVERY_INFO_OFFSET (SECFLASH_INIT_FLAG_OFFSET - SECFLASH_RECOVERY_INFO_COUNT)

/* old mng_units information, 10 block below the recovery information */
#define SECFLASH_MNG_UNITS_COUNT_ORIGIN 10
/* secflash mng_units information, 80 block below the recovery information */
#define SECFLASH_MNG_UNITS_COUNT 80
#define SECFLASH_MNG_UNITS_OFFSET (SECFLASH_RECOVERY_INFO_OFFSET - SECFLASH_MNG_UNITS_COUNT)

/* All the memory which is availble to be allocated for external use. */
#define SECFLASH_MNG_MEM_COUNT (SECFLASH_BLOCK_COUNT - SECFLASH_MNG_INFO_COUNT)
#define SECFLASH_MNG_MEM_BASE SECFLASH_MEMORY_BASE
#define SECFLASH_MNG_MEM_END (SECFLASH_MEMORY_BASE + SECFLASH_MNG_MEM_COUNT)

/* the maximum supported UUID number */
#define MAX_MNG_UNIT_MUN SECFLASH_MNG_UNITS_COUNT
/* the maximum number of */
#define ALLOCATED_SPACE_NUM (MAX_MNG_UNIT_MUN * 2)
/* the maximum supported memory space number */
#define MEM_SPACE_NUM (ALLOCATED_SPACE_NUM + 2)

/* value secflash has been inited */
#define SECFLASH_INITED 0x5A69A596

/* value secflash upgrade flag and version: V0.2 */
#define SECFLASH_UPGRADE 0x56302E32

/* recovery information is valid or not */
#define RECOVERY_INFO_VALID 0xA5
#define RECOVERY_INFO_INVALID 0x0

/* value secflash all the service is ready or not */
#define SECFLASH_IS_READY 0x695A96A5
#define SECFLASH_NOT_READY 0x0

/* Support read 1~16 block count */
#define MAX_READ_COUNT 16
/* Specially support read 256 block count */
#define MAX_READ_SPECIAL_COUNT 256
/* Support write 1~16 block count */
#define MAX_WRITE_COUNT 16

/* the maximum supported allocated block count */
#define MAX_ALLOC_COUNT ((16 * 1024) / BLOCK_SIZE)

/* general invalid array index, array index should not be negative */
#define GENERAL_INVALID_INDEX (-1)

/* flag denotes if it needs to update the system info */
#define SYSTEM_TO_UPDATE 0x69
#define SYSTEM_NOT_UPDATE 0

/* The maximum buffer size used for reading and writing data */
#define MAX_BUFFER_SIZE (SECFLASH_MNG_UNITS_COUNT * BLOCK_SIZE)

/* Low level erase function only supports 64 aligned block erasion. */
#define ERASE_BLK_CNT (1024 / BLOCK_SIZE)

/* The max supported object_id */
#define MAX_OBJECT_ID 7

/* If the mng_id is equal to this value, this mng_unit is not used. */
#define MNG_UNIT_INVALID_MNG_ID 0

/* Resolve the uuid_idx part of a mng_id */
#define mng_id_resolve_uuid_idx(mng_id) ((mng_id) & 0x1F)

/* Resolve the object_id part of a mng_id */
#define mng_id_resolve_object_id(mng_id) (((mng_id) & 0xE0) >> 5U)

/* Generate a mng_id from object_id and uuid_idx */
#define mng_id_generate(obj_id, uuid_idx) (((obj_id) << 5U) | ((uuid_idx) & 0x1F))

/* The supported memory types. */
enum memory_type {
    NON_DELETABLE = 0x5A,
    DELETABLE = 0xA5
};

/* used to record the operation type when power off */
enum operation_type {
    OP_ALLOCATE = 0x37,
    OP_FREE = 0x42,
    OP_FACTORY_RESET = 0x53
};

/* secflash management data type */
enum mng_data_type {
    MNG_DATA_INIT_FLAG = 0x06,
    MNG_DATA_RECOVERY_INFO = 0x11,
    MNG_DATA_MNG_UNIT = 0x13
};

#define MNG_UNIT_UNUSED_BYTE 7
struct mng_unit {
    /* used for identifying different allocation */
    uint8_t mng_id;
    /* not used, just used for block aligned */
    uint8_t no_use[MNG_UNIT_UNUSED_BYTE];
    /* record the starting block offset of the allocated DELETABLE memory */
    uint16_t del_off;
    /* record the block count of the allocated DELETABLE memory */
    uint16_t del_cnt;
    /* record the starting block offset of allocated NON_DELETABLE memory */
    uint16_t ndel_off;
    /* record the block count of allocated NON_DELETABLE memory */
    uint16_t ndel_cnt;
};

/* Used for recording memory spaces.
 * If count is big than zero, it denotes a free memory space.
 * If count is zero, it means the mem_space struct has not been used.
 */
struct mem_space {
    /* record the starting block offset of a memory space */
    uint16_t offset;
    /* record the block count of a memory space */
    uint16_t count;
};

/* Used for backing up current key information in case sudden power-off */
struct recovery_info {
    /* denote if the total recovery_info is valid or not */
    uint8_t valid_flag;
    /* record the operation_type */
    uint8_t op_type;
    /* record the memory_type */
    uint8_t mem_type;
    /* record mng_id infomation of mng_unit */
    uint8_t mng_id;
    /* record the index in g_mng_units array */
    uint8_t unit_idx;
    /* denote if it needs to update the system info */
    uint8_t is_sys_update;
    /* record the mng_unit offset */
    uint16_t unit_off;
    /* record the mng_unit count */
    uint16_t unit_cnt;
    /* record the system offset */
    uint16_t sys_off;
    /* record the system count */
    uint16_t sys_cnt;
};

/* all the UUID which can enjoy the secflash service.
 * g_uuid_white_list[0] is used for invalid UUID.
 */
static const TEE_UUID g_uuid_white_list[] = {
    {0},
    {0xB4B71581, 0xADD2, 0xE89F, {0xD5, 0x36, 0xF3, 0x54, 0x36, 0xDC, 0x79, 0x73}}, /* antitheft */
    {0xa32b3d00, 0xcb57, 0x11e3, {0x9c, 0x1a, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66}}, /* electric capacity */
    {0xa423e43d, 0xabfd, 0x441f, {0xb8, 0x9d, 0x39, 0xe3, 0x9f, 0x3d, 0x7f, 0x65}}, /* optics */
    {0xfd1bbfb2, 0x9a62, 0x4b27, {0x8f, 0xdb, 0xa5, 0x03, 0x52, 0x90, 0x76, 0xaf}}, /* fingerprint */
    {0xe8014913, 0xe501, 0x4d44, {0xa9, 0xd6, 0x05, 0x8e, 0xc3, 0xb9, 0x3b, 0x90}}, /* face */
    {0x42abc5f0, 0x2d2e, 0x4c3d, {0x8c, 0x3f, 0x34, 0x99, 0x78, 0x3c, 0xa9, 0x73}}, /* weaver */
    {0x431180bf, 0x7460, 0x4599, {0xa1, 0xa7, 0x11, 0x3d, 0xf7, 0xb1, 0xa6, 0x88}}, /* HiChain 2.0 */
    {0x86310d18, 0x5659, 0x47c9, {0xb2, 0x12, 0x84, 0x1a, 0x3c, 0xa4, 0xf8, 0x14}}, /* HW_KEYMASTER */
#ifdef DEF_ENG
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x61}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x62}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x63}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x64}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x65}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x66}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x67}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x68}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x69}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x6a}},
    {0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x6b}}
#endif /* DEF_ENG */
};

/* The first element in g_uuid_white_list has not been used. */
#define WHITE_LIST_INVALID_INDEX 0
/* Valid index range of g_uuid_white_list. */
#define WHITE_LIST_VALID_INDEX_START 1
#define WHITE_LIST_VALID_INDEX_END ((sizeof(g_uuid_white_list) /\
    sizeof(TEE_UUID)) - 1)

/* If there are less than 2 free spaces, no need to merge. */
#define FREE_SPACE_MERGE_THRESHHOLD 2

/* Mark if the secflash are ready to serve. */
static uint32_t g_ready_flag;

/* used to mark if the secflash has been inited */
static uint32_t g_init_flag;
/* The upgrade flag and version number. */
static uint32_t g_upgrade_flag;
/* The buffer to cache the init flag and the upgrade flag. */
static uint8_t g_init_flag_buf[BLOCK_SIZE];
/* information used for recovering from sudden power-off */
static struct recovery_info g_recovery_info;
/* structs for managing information of UUID in whitelist */
static struct mng_unit g_mng_units[MAX_MNG_UNIT_MUN];
/* structs for recording memory space */
static struct mem_space g_mem_spaces[MEM_SPACE_NUM];

/* A index of g_mem_spaces. The mem_space denoted by this index is the shared
 * memory space which can be allocated for both DELETABLE and NON_DELETABLE
 * memory. */
static int g_share_space_idx;
/* If there is no such a common memory space. Mark the division boundary. */
static uint16_t g_division_offset;

/* Point to the current TEE_UUID to be checked by g_uuid_white_list. */
static TEE_UUID *g_current_uuid;

#ifdef SECFLASH_MM_DEBUG
/*
 * @brief     : Print the management data stored in flash.
 * @param[in] : type, The type of the management data.
 * @param[out]: void.
 * @return    : void.
 */
static void secflash_mm_print_mng_data(enum mng_data_type type)
{
    int i;

    switch (type) {
    case MNG_DATA_INIT_FLAG:
        tloge("%s, i_flag=0x%x\n", __func__, g_init_flag);
        tloge("%s, i_upgrade=0x%x\n", __func__, g_upgrade_flag);
        break;
    case MNG_DATA_RECOVERY_INFO:
        tloge("%s, r_info: vflag=0x%x, otype=0x%x, mtype=0x%x, ",  \
            __func__, g_recovery_info.valid_flag, g_recovery_info.op_type, \
            g_recovery_info.mem_type);

        tloge("sflag=0x%x, id=0x%x, tidx=%u, uoff=%u, ucnt=%u, ",\
            g_recovery_info.is_sys_update, g_recovery_info.mng_id, \
            g_recovery_info.unit_idx, g_recovery_info.unit_off, \
            g_recovery_info.unit_cnt);
        tloge("soff=%u, scnt=%u\n", g_recovery_info.sys_off, \
            g_recovery_info.sys_cnt);
        break;
    case MNG_DATA_MNG_UNIT:
        tloge("%s, units info:\n", __func__);
        for (i = 0; i < MAX_MNG_UNIT_MUN; i++) {
            if (g_mng_units[i].mng_id != MNG_UNIT_INVALID_MNG_ID) {
                tloge(">\tidx=%u: id=%u, doff=%u, dcnt=%u, ", \
                    i, g_mng_units[i].mng_id, g_mng_units[i].del_off, \
                    g_mng_units[i].del_cnt);
                tloge(">\tnoff=%u, ncnt=%u\n", \
                    g_mng_units[i].ndel_off, g_mng_units[i].ndel_cnt);
            }
        }
        break;
    default:
        break;
    }
    tloge("\n");
}

/*
 * @brief     : Print the secflash all management data.
 * @param[in] : void.
 * @param[out]: void.
 * @return    : void.
 */
static void secflash_mm_print_data(void)
{
    int i;

    tloge("%s: ready flag=0x%x\n", __func__, g_ready_flag);
    tloge("%s: key index=%d\n", __func__, g_share_space_idx);
    tloge("%s: key offset=%u\n", __func__, g_division_offset);
    secflash_mm_print_mng_data(MNG_DATA_INIT_FLAG);
    secflash_mm_print_mng_data(MNG_DATA_RECOVERY_INFO);
    secflash_mm_print_mng_data(MNG_DATA_MNG_UNIT);
    tloge("%s: mem spaces\n", __func__);
    for (i = 0; i < MEM_SPACE_NUM; i++) {
        if (g_mem_spaces[i].count > 0)
            tloge(">\tidx=%d, off=%u, cnt=%u\n", i, g_mem_spaces[i].offset, g_mem_spaces[i].count);
    }
    tloge("\n");
    tloge("%s******************************END\n\n", __func__);
}
#endif

/*
 * @brief     : Set the offset of  the mem_space whose count is zero to SECFLASH_MEMORY_END before sort. So these
 *                 mem_space will be sorted in the end positions.
 * @param[in] : mem_spaces, Array of memory space to be sorted.
 * @param[in] : bound, The valid size of the memory space array.
 * @param[out]: void
 * @return    : void.
 */
static void secflash_mm_sort_prepare(struct mem_space *mem_spaces, int bound)
{
    int i;

    for (i = 0; i < bound; i++) {
        /* If count is euqal to 0, it means this struct has not been used for denoting any space. */
        if (mem_spaces[i].count == 0)
            /* Set the value to be the biggest. So they will in the end position after sorting. */
            mem_spaces[i].offset = SECFLASH_MEMORY_END;
    }
}

/*
 * @brief     : Reset the offset of  the mem_space whose count is zero to 0 after sort.
 * @param[in] : mem_spaces, Array of memory space to be sorted.
 * @param[in] : bound, The valid size of the memory space array.
 * @param[out]: void
 * @return    : The size of sorted memory space excluding no used space.
 */
static int secflash_mm_sort_after(struct mem_space *mem_spaces, int bound)
{
    int i;
    int index;

    index = bound;
    for (i = 0; i < bound; i++) {
        /* Find all unused element and reset the offset to be 0. */
        if (mem_spaces[i].count == 0) {
            mem_spaces[i].offset = 0;
            /* Set the length of valid mem space the first time met unused element. */
            if (index == bound)
                index = i;
        }
    }
    return index;
}

/*
 * @brief     : Sort the memory space by offset from low to high
 * @param[in] : mem_spaces, Array of memory space to be sorted.
 * @param[in] : bound, The valid size of the memory space array.
 * @param[out]: void
 * @return    : The size of sorted memory space excluding no used space.
 */
static int secflash_mm_sort_spaces(struct mem_space *mem_spaces, int bound)
{
    int i;
    int j;
    int index;
    uint16_t tmp_off;
    uint16_t tmp_cnt;

    secflash_mm_sort_prepare(mem_spaces, bound);

    /* Use selec sort to sort all elements in mem_spaces from low to high by offset. */
    for (i = 0; i < bound - 1; i++) {
        index = i;
        for (j = i + 1; j < bound; j++) {
            if (mem_spaces[index].offset > mem_spaces[j].offset)
                index = j;
        }
        if (i != index) {
            tmp_off = mem_spaces[i].offset;
            tmp_cnt = mem_spaces[i].count;
            mem_spaces[i].offset = mem_spaces[index].offset;
            mem_spaces[i].count = mem_spaces[index].count;
            mem_spaces[index].offset = tmp_off;
            mem_spaces[index].count = tmp_cnt;
        }
    }
    index = secflash_mm_sort_after(mem_spaces, bound);
    return index;
}

/*
 * @brief     : Get the management data offset and count.
 * @param[in] : type, The type of the management data.
 * @param[in] : unit_idx, The index in g_mng_units array.
 * @param[out]: blk_off, Return the block offset of the management data.
 * @param[out]: blk_cnt, Return the block count of the management data.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_get_mng_data_info(enum mng_data_type type, int unit_idx,
    uint16_t *blk_off, uint16_t *blk_cnt)
{
    switch (type) {
    case MNG_DATA_INIT_FLAG:
        *blk_off = SECFLASH_INIT_FLAG_OFFSET;
        *blk_cnt = SECFLASH_INIT_FLAG_COUNT;
        break;
    case MNG_DATA_RECOVERY_INFO:
        *blk_off = SECFLASH_RECOVERY_INFO_OFFSET;
        *blk_cnt = SECFLASH_RECOVERY_INFO_COUNT;
        break;
    case MNG_DATA_MNG_UNIT:
        if (unit_idx != GENERAL_INVALID_INDEX) {
            *blk_off = SECFLASH_MNG_UNITS_OFFSET + unit_idx;
            *blk_cnt = 1;
        } else {
            *blk_off = SECFLASH_MNG_UNITS_OFFSET;
            *blk_cnt = SECFLASH_MNG_UNITS_COUNT;
        }
        break;
    default:
        return SF_MM_INVALID_MNG_DATA;
    }
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Read data from secflash.
 * @param[in] : blk_off, The block offset to read.
 * @param[in] : blk_cnt, The block count to read.
 * @param[in] : buf_size, The size of buffer.
 * @param[out]: buffer, Buffer to contain the read data.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_read_data(uint32_t blk_off, uint32_t blk_cnt, uint8_t *buffer, uint32_t buf_size)
{
    uint32_t ret;
    uint16_t read_cnt;
    uint8_t *buf_pos = NULL;

    buf_pos = buffer;
    while (blk_cnt > 0) {
        read_cnt = blk_cnt;
        if (read_cnt > MAX_READ_COUNT)
            read_cnt = MAX_READ_COUNT;
        ret = secflash_read_blocks(SECFLASH_SECURE_STORAGE_TYPE, blk_off, read_cnt, buf_pos, buf_size);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x, blk_off=%u, read_cnt=%u\n", __func__, ret, blk_off, read_cnt);
            return ret;
        }
        blk_cnt -= read_cnt;
        blk_off += read_cnt;
        buf_pos += block_to_byte(read_cnt);
        buf_size -= block_to_byte(read_cnt);
    }
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Buffer the init flag and upgrade information.
 * @param[in] : buffer, The buffer to cache the data.
 * @param[in] : buf_len, The length of the buffer.
 * @param[out]: void
 * @return    : Security function operation status
 */
static errno_t secflash_mm_init_flag_read_process(uint8_t *buffer, uint32_t buf_len)
{
    errno_t status;

    if (buf_len < sizeof(g_init_flag_buf))
        return SF_MM_MEMCPY_FAIL;

    status = memcpy_s((uint8_t *)&g_init_flag, sizeof(g_init_flag),
                buffer, sizeof(g_init_flag));
    if (status != EOK)
        return SF_MM_MEMCPY_FAIL;

    status = memcpy_s((uint8_t *)&g_upgrade_flag, sizeof(g_upgrade_flag),
        buffer + sizeof(g_init_flag), sizeof(g_upgrade_flag));
    if (status != EOK)
        return SF_MM_MEMCPY_FAIL;

    status = memcpy_s(g_init_flag_buf, sizeof(g_init_flag_buf),
        buffer, sizeof(g_init_flag_buf));
    if (status != EOK)
        return SF_MM_MEMCPY_FAIL;

    return EOK;
}


/*
 * @brief     : Read specific management data
 * @param[in] : type, The type of the management data.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_read_mng_data(enum mng_data_type type)
{
    uint8_t buffer[MAX_BUFFER_SIZE] = {0};
    uint16_t blk_off;
    uint16_t blk_cnt;
    errno_t st;
    uint32_t ret;

    ret = secflash_mm_get_mng_data_info(type, GENERAL_INVALID_INDEX, &blk_off, &blk_cnt);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    ret = secflash_mm_read_data(blk_off, blk_cnt, buffer, sizeof(buffer));
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x, blk_off=%u, read_cnt=%u\n", __func__, ret, blk_off, blk_cnt);
        return ret;
    }

    st = EOK;
    switch (type) {
    case MNG_DATA_INIT_FLAG:
        st = secflash_mm_init_flag_read_process(buffer, sizeof(buffer));
        break;
    case MNG_DATA_RECOVERY_INFO:
        st = memcpy_s((uint8_t *)&g_recovery_info, sizeof(g_recovery_info),
            buffer, sizeof(g_recovery_info));
        break;
    case MNG_DATA_MNG_UNIT:
        st = memcpy_s((uint8_t *)&g_mng_units[0], sizeof(g_mng_units),
            buffer, sizeof(g_mng_units));
        break;
    default:
        break;
    }

    if (st != EOK)
        ret = SF_MM_MEMCPY_FAIL;

    return ret;
}

/*
 * @brief     : Write data from secflash.
 * @param[in] : blk_off, The block offset to write.
 * @param[in] : blk_cnt, The block count to write.
 * @param[in] : buf_size, The size of buffer.
 * @param[out]: buffer, Buffer to contain the written data.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_write_data(uint32_t blk_off, uint32_t blk_cnt, uint8_t *buffer)
{
    uint32_t ret;
    uint16_t write_cnt;
    uint8_t *buf_pos = NULL;

    buf_pos = buffer;
    while (blk_cnt > 0) {
        write_cnt = blk_cnt;
        if (write_cnt > MAX_WRITE_COUNT)
            write_cnt = MAX_WRITE_COUNT;

        ret = secflash_write_blocks(SECFLASH_SECURE_STORAGE_TYPE, blk_off, write_cnt, buf_pos);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x, off=%u, cnt=%u\n", __func__, ret, blk_off, write_cnt);
            return ret;
        }
        blk_cnt -= write_cnt;
        blk_off += write_cnt;
        buf_pos += block_to_byte(write_cnt);
    }
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Before writing init flag data, combine the data.
 * @param[in] : buffer, The buffer to cache the data.
 * @param[in] : buf_len, The length of the buffer.
 * @param[out]: void
 * @return    : Security function operation status
 */
static errno_t secflash_mm_init_flag_write_preprocess(uint8_t *buffer, uint32_t buf_len)
{
    errno_t status;
    uint32_t size;

    status = memcpy_s(buffer, buf_len,
                (uint8_t *)&g_init_flag, sizeof(g_init_flag));
    if (status != EOK) {
        tloge("%s, rv=0x%x\n", __func__, SF_MM_MEMCPY_FAIL);
        return SF_MM_MEMCPY_FAIL;
    }

    buffer += sizeof(g_init_flag);
    buf_len -= sizeof(g_init_flag);
    status = memcpy_s(buffer, buf_len, (uint8_t *)&g_upgrade_flag, sizeof(g_upgrade_flag));
    if (status != EOK) {
        tloge("%s, rv=0x%x\n", __func__, SF_MM_MEMCPY_FAIL);
        return SF_MM_MEMCPY_FAIL;
    }

    buffer += sizeof(g_upgrade_flag);
    buf_len -= sizeof(g_upgrade_flag);
    size = BLOCK_SIZE - sizeof(g_init_flag) - sizeof(g_upgrade_flag);
    status = memset_s(buffer, buf_len, 0, size);
    if (status != EOK) {
        tloge("%s, rv=0x%x\n", __func__, SF_MM_MEMSET_FAIL);
        return SF_MM_MEMSET_FAIL;
    }

    return EOK;
}

/*
 * @brief     : Write specific management data
 * @param[in] : type, The type of the management data.
 * @param[in] : unit_idx, The index in g_mng_units array.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_write_mng_data(enum mng_data_type type, int unit_idx)
{
    uint8_t buffer[MAX_BUFFER_SIZE] = {0};
    uint16_t blk_off;
    uint16_t blk_cnt;
    errno_t status;
    uint32_t ret;

    ret = secflash_mm_get_mng_data_info(type, unit_idx, &blk_off, &blk_cnt);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    switch (type) {
    case MNG_DATA_INIT_FLAG:
        status = secflash_mm_init_flag_write_preprocess(buffer, sizeof(buffer));
        if (status != EOK)
            return status;
        break;
    case MNG_DATA_RECOVERY_INFO:
        status = memcpy_s(buffer, sizeof(buffer),
            (uint8_t *)&g_recovery_info, sizeof(g_recovery_info));
        break;
    case MNG_DATA_MNG_UNIT:
        if (unit_idx != GENERAL_INVALID_INDEX) {
            status = memcpy_s(buffer, sizeof(buffer), (uint8_t *)&g_mng_units[unit_idx], sizeof(struct mng_unit));
        } else {
            status = memcpy_s(buffer, sizeof(buffer), (uint8_t *)&g_mng_units[0], sizeof(g_mng_units));
        }
        break;
    default:
        break;
    }
    if (status != EOK) {
        ret = SF_MM_MEMCPY_FAIL;
        return ret;
    }

    ret = secflash_mm_write_data(blk_off, blk_cnt, buffer);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x, off=%u, cnt=%u\n", __func__, ret, blk_off, blk_cnt);

    return ret;
}

/*
 * @brief     : Update system info.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : is_sys_update, If to update system information.
 * @param[in] : sys_off, System section block offset.
 * @param[in] : sys_cnt, System section block count.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_update_system_info(uint8_t mem_type, uint8_t is_sys_update,
    uint16_t sys_off, uint16_t sys_cnt)
{
    uint32_t ret;
    uint32_t sys_tag;

    ret = SF_MM_SUCCESS;
    if (is_sys_update != SYSTEM_TO_UPDATE) {
        return ret;
    }

    if (mem_type == DELETABLE) {
        sys_tag = HIGHREPAIR_ON_FACTORYRECOVERY_ON_TAG;
    } else {
        sys_tag = HIGHREPAIR_ON_FACTORYRECOVERY_OFF_TAG;
    }

    ret = secflash_set_region_info(SECFLASH_SECURE_STORAGE_TYPE, sys_tag, sys_off, sys_cnt);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x, type=0x%x, off=%u, cnt=%u\n", __func__, ret, mem_type, sys_off, sys_cnt);

    return ret;
}

/*
 * @brief     : Use self-defined erase function to erase data.
 * @param[in] : blk_off, The block index to erase from.
 * @param[in] : blk_cnt, The block count to erase.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_erase_data_self(uint16_t blk_off, uint16_t blk_cnt)
{
    uint8_t buffer[MAX_WRITE_COUNT * BLOCK_SIZE] = {0};
    errno_t status;
    uint32_t ret;
    uint16_t erase_index;
    uint16_t erase_count;
    uint16_t erase_end;

    erase_index = blk_off;
    erase_end = blk_off + blk_cnt;
    status = memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));
    if (status != EOK) {
        ret = SF_MM_MEMSET_FAIL;
        return ret;
    }
    while (erase_index < erase_end) {
        erase_count = MAX_WRITE_COUNT;
        if (erase_count > erase_end - erase_index)
            erase_count = erase_end - erase_index;

#ifdef SECFLASH_MM_DEBUG
        tloge("%s, off=%u, cnt=%u\n", __func__, erase_index, erase_count);
#endif
        ret = secflash_write_blocks(SECFLASH_SECURE_STORAGE_TYPE, erase_index, erase_count, buffer);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x\n", __func__, ret);
            return ret;
        }
        erase_index += erase_count;
    }
    return ret;
}

/*
 * @brief     : When to allocate space, erase the space data before user get it.
 * @param[in] : blk_off, The block index to erase from.
 * @param[in] : blk_cnt, The block count to erase.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_erase_data(uint16_t blk_off, uint16_t blk_cnt)
{
    uint32_t ret;
    uint16_t erase_index;
    uint16_t erase_count;

    if (blk_cnt < ERASE_BLK_CNT) {
        return secflash_mm_erase_data_self(blk_off, blk_cnt);
    }

    erase_index = blk_off;
    if (erase_index % ERASE_BLK_CNT != 0) {
        erase_count = ERASE_BLK_CNT - (erase_index % ERASE_BLK_CNT);
        if (erase_count > blk_cnt)
            erase_count = blk_cnt;

        ret = secflash_mm_erase_data_self(erase_index, erase_count);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x\n", __func__, ret);
            return ret;
        }
        erase_index += erase_count;
        blk_cnt -= erase_count;
    }
    if (blk_cnt >= ERASE_BLK_CNT) {
        erase_count = blk_cnt - blk_cnt % ERASE_BLK_CNT;
        blk_cnt -= erase_count;

        while (erase_count > 0) {
            ret = secflash_erase_blocks(SECFLASH_SECURE_STORAGE_TYPE, erase_index, ERASE_BLK_CNT);
            if (ret != SF_MM_SUCCESS) {
                tloge("%s, rv=0x%x\n", __func__, ret);
                return ret;
            }
            erase_index += ERASE_BLK_CNT;
            erase_count -= ERASE_BLK_CNT;
        }
    }
    if (blk_cnt > 0) {
        ret = secflash_mm_erase_data_self(erase_index, blk_cnt);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x\n", __func__, ret);
            return ret;
        }
    }
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Initialize the secflash memory management data complelely
 * @param[in] : void
 * @param[out]: void
 * @return    : operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_init_completely(void)
{
    uint32_t ret;
    enum mng_data_type type;

#ifdef SECFLASH_MM_DEBUG
    tloge("Enter %s\n", __func__);
#endif
    ret = secflash_mm_erase_data_self(SECFLASH_MNG_INFO_BASE, SECFLASH_MNG_INFO_COUNT);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_update_system_info(DELETABLE, SYSTEM_TO_UPDATE, 0, 0);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_update_system_info(NON_DELETABLE, SYSTEM_TO_UPDATE, SECFLASH_MNG_MEM_END, SECFLASH_MNG_INFO_COUNT);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    g_init_flag = SECFLASH_INITED;
    g_upgrade_flag = SECFLASH_UPGRADE;
    type = MNG_DATA_INIT_FLAG;
    ret = secflash_mm_write_mng_data(type, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x, type=0x%x\n", __func__, ret, type);

#ifdef SECFLASH_MM_DEBUG
    tloge("Exit %s\n", __func__);
#endif
    return ret;
}

/*
 * @brief     : Reset the DELETABLE info of all mng_unit. If no NON_DELETABLE info, recycle it.
 * @param[in] : void
 * @param[out]: void
 * @return    : void
 */
static void secflash_mm_reset_units_deletable_info(void)
{
    int i;

    /* Clean all the DELETABLE infomation in g_mng_units */
    for (i = 0; i < MAX_MNG_UNIT_MUN; i++) {
        if (g_mng_units[i].del_cnt != 0) {
            g_mng_units[i].del_off = 0;
            g_mng_units[i].del_cnt = 0;
            /* If NON_DELETABLE info is none, recycle this uuid_unit. */
            if (g_mng_units[i].ndel_cnt == 0) {
                g_mng_units[i].ndel_off = 0;
                g_mng_units[i].mng_id = MNG_UNIT_INVALID_MNG_ID;
            }
        }
    }
}

/*
 * @brief     : Check if the memory type is valid.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_check_mem_type(uint32_t mem_type)
{
    if (mem_type != NON_DELETABLE && mem_type != DELETABLE) {
        tloge("%s, type=0x%x\n", __func__, mem_type);
        return SF_MM_INVALID_MEM_TYPE;
    }
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Check the recovery_info if valid.
 * @param[in] : void
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_recover_info_check(void)
{
    uint32_t ret;
    uint8_t mng_id;
    uint8_t uuid_idx;
    uint8_t unit_idx;
    enum memory_type mem_type;

    mng_id = g_recovery_info.mng_id;
    uuid_idx = mng_id_resolve_uuid_idx(mng_id);
    unit_idx = g_recovery_info.unit_idx;
    mem_type = (enum memory_type)g_recovery_info.mem_type;

    ret = secflash_mm_check_mem_type(mem_type);
    if (ret != SF_MM_SUCCESS)
        return ret;

    if (uuid_idx > WHITE_LIST_VALID_INDEX_END)
        return SF_MM_RECOVER_INVALID_UUID_IDX;

    if (unit_idx >= MAX_MNG_UNIT_MUN)
        return SF_MM_RECOVER_INVALID_UNIT_IDX;

    return SF_MM_SUCCESS;
}

/*
 * @brief     : Recover g_mng_units data.
 * @param[in] : void
 * @param[out]: recov_unit_idx, Return the updated unit index.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_recover_unit(int *recov_unit_idx)
{
    uint32_t ret;
    uint8_t unit_idx;
    enum operation_type op_type;
    enum memory_type mem_type;

    ret = secflash_mm_recover_info_check();
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    unit_idx = g_recovery_info.unit_idx;
    op_type = (enum operation_type)g_recovery_info.op_type;
    mem_type = (enum memory_type)g_recovery_info.mem_type;

    switch (op_type) {
    case OP_ALLOCATE:
    case OP_FREE:
        /* Adopt rollback recovery strategy. Set the mng_unit info to be
         * the origin value. */
        g_mng_units[unit_idx].mng_id = g_recovery_info.mng_id;
        if (mem_type == DELETABLE) {
            g_mng_units[unit_idx].del_off = g_recovery_info.unit_off;
            g_mng_units[unit_idx].del_cnt = g_recovery_info.unit_cnt;
        } else {
            g_mng_units[unit_idx].ndel_off = g_recovery_info.unit_off;
            g_mng_units[unit_idx].ndel_cnt = g_recovery_info.unit_cnt;
        }
        *recov_unit_idx = unit_idx;
        break;
    case OP_FACTORY_RESET:
        secflash_mm_reset_units_deletable_info();
        /* All g_mng_units need to be saved. */
        *recov_unit_idx = GENERAL_INVALID_INDEX;
        break;
    default:
        ret = SF_MM_RECOVER_INVALID_OP_TYPE;
        break;
    }
    return ret;
}

/*
 * @brief     : Recover g_mng_units data and update system info.
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_recover_data(void)
{
    uint32_t ret;
    int recover_uint_idx;
    enum memory_type mem_type;

    mem_type = (enum memory_type)g_recovery_info.mem_type;

    ret = secflash_mm_recover_unit(&recover_uint_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    ret = secflash_mm_write_mng_data(MNG_DATA_MNG_UNIT, recover_uint_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_update_system_info(mem_type, g_recovery_info.is_sys_update,
        g_recovery_info.sys_off, g_recovery_info.sys_cnt);
    return ret;
}


/*
 * @brief     : Use recovery_info to recover management data from sudden power-off
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_recovery(void)
{
    uint32_t ret;
    uint8_t unit_idx;
    enum operation_type op_type;
    enum memory_type mem_type;

    ret = secflash_mm_read_mng_data(MNG_DATA_RECOVERY_INFO);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    if (g_recovery_info.valid_flag != RECOVERY_INFO_VALID)
        return SF_MM_SUCCESS;

    unit_idx = g_recovery_info.unit_idx;
    op_type = (enum operation_type)g_recovery_info.op_type;
    mem_type = (enum memory_type)g_recovery_info.mem_type;
    /* log the recovery information */
    tloge("%s: 0x%x, 0x%x, 0x%x, 0x%x, %u, %u, %u, 0x%x, %u, %u\n", __func__,\
        g_recovery_info.valid_flag, op_type, mem_type, \
        g_recovery_info.mng_id, unit_idx, \
        g_recovery_info.unit_off, g_recovery_info.unit_cnt, \
        g_recovery_info.is_sys_update, g_recovery_info.sys_off, \
        g_recovery_info.sys_cnt);

    ret = secflash_mm_recover_data();
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    g_recovery_info.valid_flag = RECOVERY_INFO_INVALID;
    ret = secflash_mm_write_mng_data(MNG_DATA_RECOVERY_INFO, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x\n", __func__, ret);

    return ret;
}

/*
 * @brief     : Generate allocated mem spaces by g_mng_units.
 * @param[in] : alloc_spaces, The allocate mem space array.
 * @param[in] : alloc_num, The allocated mem space num.
 * @param[out]: max_del_end, Return the maximum DELETABLE end offset.
 * @param[out]: min_ndel_start, Return the minimum NON_DELETABLE start offset.
 * @return    : void
 */
static void secflash_mm_get_allocated_spaces(struct mem_space *alloc_spaces, int alloc_num,
    uint16_t *max_del_end, uint16_t *min_ndel_start)
{
    int i;
    int j;

    for (j = 0; j < alloc_num; j++) {
        alloc_spaces[j].offset = 0;
        alloc_spaces[j].count = 0;
    }

    *max_del_end = 0;
    *min_ndel_start = SECFLASH_MNG_MEM_COUNT;
    for (i = 0, j = 0; i < MAX_MNG_UNIT_MUN && j < alloc_num ; i++) {
        if (g_mng_units[i].mng_id != MNG_UNIT_INVALID_MNG_ID) {
            if (g_mng_units[i].del_cnt > 0) {
                alloc_spaces[j].offset = g_mng_units[i].del_off;
                alloc_spaces[j].count = g_mng_units[i].del_cnt;
                *max_del_end = *max_del_end < (g_mng_units[i].del_off + g_mng_units[i].del_cnt) ?
                    (g_mng_units[i].del_off + g_mng_units[i].del_cnt) : *max_del_end;
                j++;
            }
            if (g_mng_units[i].ndel_cnt > 0) {
                alloc_spaces[j].offset = g_mng_units[i].ndel_off;
                alloc_spaces[j].count = g_mng_units[i].ndel_cnt;
                *min_ndel_start = *min_ndel_start > g_mng_units[i].ndel_off ?
                    g_mng_units[i].ndel_off : *min_ndel_start;
                j++;
            }
        }
    }
}

/*
 * @brief     : To form the free mem spaces by alloc_spaces.
 * @param[in] : alloc_spaces, The allocate mem space array.
 * @param[in] : alloc_num, The allocate mem space array bound.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_get_free_spaces(struct mem_space *alloc_spaces, int bound)
{
    int i;
    int j;
    uint16_t offset;

    offset = 0;
    for (i = 0, j = 0; i < MEM_SPACE_NUM && j < bound; j++) {
        if (alloc_spaces[j].count == 0)
            break;

        if (alloc_spaces[j].offset > offset) {
            g_mem_spaces[i].offset = offset;
            g_mem_spaces[i].count = alloc_spaces[j].offset - offset;
            offset += alloc_spaces[j].count + g_mem_spaces[i].count;
            i++;
        } else if (alloc_spaces[j].offset == offset) {
            offset += alloc_spaces[j].count;
        } else {
            return SF_MM_INIT_SPACE_OVERLAP;
        }
    }

    if (j > 0)
        j--;

    if (alloc_spaces[j].offset + alloc_spaces[j].count > SECFLASH_MNG_MEM_COUNT)
        return SF_MM_INIT_EXCEED_ROOF;

    if (i >= MEM_SPACE_NUM)
        return SF_MM_INIT_NO_MEM_SPACE;

    g_mem_spaces[i].offset = alloc_spaces[j].offset + alloc_spaces[j].count;
    g_mem_spaces[i].count = SECFLASH_MNG_MEM_COUNT - g_mem_spaces[i].offset;
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Generate the free space information from the allocated memory.
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_generate_mem_spaces(void)
{
    int i;
    int bound;
    struct mem_space alloc_spaces[ALLOCATED_SPACE_NUM];
    uint16_t max_del_end;
    uint16_t min_ndel_start;
    uint32_t ret;

    secflash_mm_get_allocated_spaces(&alloc_spaces[0], ALLOCATED_SPACE_NUM,
        &max_del_end, &min_ndel_start);

    bound = secflash_mm_sort_spaces(&alloc_spaces[0], ALLOCATED_SPACE_NUM);

    ret = secflash_mm_get_free_spaces(&alloc_spaces[0], bound);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    if (max_del_end == min_ndel_start) {
        g_division_offset = max_del_end;
    } else {
        for (i = 0; i < MEM_SPACE_NUM; i++) {
            if ((g_mem_spaces[i].offset == max_del_end) &&
                 (g_mem_spaces[i].offset + g_mem_spaces[i].count) == min_ndel_start) {
                g_share_space_idx = i;
                break;
            }
        }
    }
    if (g_share_space_idx == GENERAL_INVALID_INDEX && g_division_offset == SECFLASH_MEMORY_END) {
        ret = SF_MM_INIT_SPACE_OVERLAP;
        tloge("%s, rv=0x%x, offset=%u\n", __func__, ret, g_division_offset);
    }
    return ret;
}

/*
 * @brief     : Reset management data if factory reset has happened.
 * @param[in] : void
 * @param[out]: void
 * @return    : void
 */
static uint32_t secflash_mm_factory_reset(void)
{
    uint32_t ret;
    enum mng_data_type type;

    g_recovery_info.valid_flag = RECOVERY_INFO_VALID;
    g_recovery_info.op_type = OP_FACTORY_RESET;
    g_recovery_info.mem_type = DELETABLE;
    g_recovery_info.is_sys_update = SYSTEM_TO_UPDATE;
    g_recovery_info.sys_off = 0;
    g_recovery_info.sys_cnt = 0;

    type = MNG_DATA_RECOVERY_INFO;
    ret = secflash_mm_write_mng_data(type, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x, type=0x%x\n", __func__, ret, type);
        return ret;
    }

    secflash_mm_reset_units_deletable_info();

    type = MNG_DATA_MNG_UNIT;
    ret = secflash_mm_write_mng_data(type, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x, type=0x%x\n", __func__, ret, type);
        return ret;
    }
    ret = secflash_mm_update_system_info(DELETABLE, SYSTEM_TO_UPDATE, 0, 0);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_set_partition_state(PARTITION_INIT_COMPLETE_STATE);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    g_recovery_info.valid_flag = RECOVERY_INFO_INVALID;
    type = MNG_DATA_RECOVERY_INFO;
    ret = secflash_mm_write_mng_data(type, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x, type=0x%x\n", __func__, ret, type);

    return ret;
}

/*
 * @brief     : Initialize the secflash management data, prepare for serving.
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_process_fatctory_status(void)
{
    uint32_t ret;
    uint32_t fact_st;

    ret = secflash_get_partition_state(&fact_st);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    tloge("%s, st=0x%x\n", __func__, fact_st);
    switch (fact_st) {
    case PARTITION_FACTORYRECOVERY_RUNNING_STATE:
        ret = secflash_factory_recovery(~0);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x\n", __func__, ret);
            return ret;
        }
        /* fall-through */
    case PARTITION_FACTORYRECOVERY_COMPLETE_STATE:
        ret = secflash_mm_factory_reset();
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x\n", __func__, ret);
            return ret;
        }
        break;
    case PARTITION_INIT_COMPLETE_STATE:
        break;
    default:
        ret = SF_MM_INIT_FACTORY_STATUS_NOT_KNOWN;
        tloge("%s, st=0x%x\n", __func__, fact_st);
        break;
    }
    return ret;
}

/*
 * @brief     : Initialize management data.
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_initialize_data(void)
{
    uint32_t ret;
    errno_t st;

    g_ready_flag = SECFLASH_NOT_READY;
    g_init_flag = 0;
    g_share_space_idx = GENERAL_INVALID_INDEX;
    g_division_offset = SECFLASH_MEMORY_END;
    g_current_uuid = NULL;

    ret = SF_MM_MEMSET_FAIL;
    st = memset_s((uint8_t *)&g_recovery_info, sizeof(g_recovery_info), 0, sizeof(g_recovery_info));
    if (st != EOK) {
        tloge("%s, rv=0x%x, tc=0x%x\n", __func__, ret, st);
        return ret;
    }

    st = memset_s((uint8_t *)&g_mng_units[0], sizeof(g_mng_units), 0, sizeof(g_mng_units));
    if (st != EOK) {
        tloge("%s, rv=0x%x, tc=0x%x\n", __func__, ret, st);
        return ret;
    }

    st = memset_s((uint8_t *)&g_mem_spaces[0], sizeof(g_mem_spaces), 0, sizeof(g_mem_spaces));
    if (st != EOK) {
        tloge("%s, rv=0x%x, tc=0x%x\n", __func__, ret, st);
        return ret;
    }
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Recover and init all the management data.
 * @param[in] : void
 * @param[out]: void
 * @return    : void
 */
static void secflash_mm_reinit(void)
{
    secflash_mm_init(SF_MM_SUCCESS);
    tloge("%s, try reinit, ready=0x%x\n", __func__, g_ready_flag);
}

/*
 * @brief     : Check if to execute upgrade.
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_check_upgrade(void)
{
    uint32_t ret;
    bool is_need_upgrade = false;
    uint32_t count;
    uint8_t reserver[BLOCK_SIZE - sizeof(g_init_flag) - sizeof(g_upgrade_flag)] = {0};

    count = sizeof(g_init_flag) + sizeof(g_upgrade_flag);
    if (memcmp((g_init_flag_buf + count), reserver, sizeof(reserver)) != 0)
        is_need_upgrade = true;

    if (g_upgrade_flag != SECFLASH_UPGRADE)
        is_need_upgrade = true;

    if (is_need_upgrade == false)
        return SF_MM_SUCCESS;

    count = SECFLASH_MNG_INFO_COUNT - SECFLASH_INIT_FLAG_COUNT -
        SECFLASH_RECOVERY_INFO_COUNT - SECFLASH_MNG_UNITS_COUNT_ORIGIN;
    ret = secflash_mm_erase_data_self(SECFLASH_MNG_INFO_BASE, count);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    g_upgrade_flag = SECFLASH_UPGRADE;
    ret = secflash_mm_write_mng_data(MNG_DATA_INIT_FLAG, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x\n", __func__, ret);

    return ret;
}

/*
 * @brief     : Initialize data from the secflash management data.
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_init_from_past(void)
{
    uint32_t ret;

    ret = secflash_mm_check_upgrade();
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return SF_MM_UPGRADE_FAIL;
    }
    ret = secflash_mm_read_mng_data(MNG_DATA_MNG_UNIT);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    ret = secflash_mm_recovery();
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_process_fatctory_status();
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x\n", __func__, ret);

    return ret;
}

/*
 * @brief     : Initialize the secflash management data, prepare for serving.
 * @param[in] : state, The externel execution state.
 * @param[out]: void
 * @return    : void
 */
void secflash_mm_init(uint32_t state)
{
    uint32_t ret;

    if (state != SF_MM_SUCCESS) {
        g_ready_flag = state;
        tloge("%s stop because last state [0x%x] failed!\n", __func__, g_ready_flag);
        return;
    }

    ret = secflash_mm_initialize_data();
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return;
    }

    ret = secflash_mm_read_mng_data(MNG_DATA_INIT_FLAG);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return;
    }
    if (g_init_flag != SECFLASH_INITED) {
        ret = secflash_mm_init_completely();
    } else {
        ret = secflash_mm_init_from_past();
    }
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return;
    }

    ret = secflash_mm_generate_mem_spaces();
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return;
    }
    g_ready_flag = SECFLASH_IS_READY;
    tloge("%s, successfully!\n", __func__);
}

/*
 * @brief     : Merge the adjacent free memory spaces to a continuous big one.
 * @param[in] : void
 * @param[out]: void
 * @return    : The size of sorted memory space excluding no used space.
 */
static int secflash_mm_merge_free_space(void)
{
    int i;
    int bound;
    uint16_t key_off;
    uint16_t key_cnt;
    bool has_key_index = false;

    if (g_share_space_idx != GENERAL_INVALID_INDEX) {
        key_off = g_mem_spaces[g_share_space_idx].offset;
        key_cnt = g_mem_spaces[g_share_space_idx].count;
        has_key_index = true;
    }

    bound = secflash_mm_sort_spaces(&g_mem_spaces[0], MEM_SPACE_NUM);

    if (has_key_index) {
        for (i = 0; i < bound; i++) {
            if (g_mem_spaces[i].offset == key_off && g_mem_spaces[i].count == key_cnt)
                g_share_space_idx = i;
        }
    }

    if (bound < FREE_SPACE_MERGE_THRESHHOLD) {
        /* If there is no more than 1 element, no need merging */
        return bound;
    }
    /* From the last but one. */
    for (i = bound - FREE_SPACE_MERGE_THRESHHOLD; i >= 0; i--) {
        if (g_mem_spaces[i].count + g_mem_spaces[i].offset == g_mem_spaces[i + 1].offset) {
            /* Merge the space to the front one. */
            g_mem_spaces[i].count += g_mem_spaces[i + 1].count;
            g_mem_spaces[i + 1].offset = 0;
            g_mem_spaces[i + 1].count = 0;
            if (g_share_space_idx == i + 1)
                g_share_space_idx = i;
        }
    }
    return bound;
}

/*
 * @brief     : Check if the uuid is in white list.
 * @param[out]: uuid_idx, The valid index in g_uuid_white_list.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_check_uuid(uint8_t *uuid_idx)
{
    int i;

    *uuid_idx = WHITE_LIST_INVALID_INDEX;
    if (g_current_uuid == NULL) {
        tloge("%s, null TEE_UUID access\n", __func__);
        return SF_MM_NULL_POINTER;
    }
    i = WHITE_LIST_VALID_INDEX_START;
    for (; i <= (int)WHITE_LIST_VALID_INDEX_END; i++) {
        if (memcmp((uint8_t *)&g_uuid_white_list[i], (uint8_t *)g_current_uuid,
            sizeof(TEE_UUID)) == 0) {
            *uuid_idx = i;
            return SF_MM_SUCCESS;
        }
    }
    return SF_MM_INVALID_UUID;
}

/*
 * @brief     : Check the input size, offset, length to see if is valid.
 * @param[in] : param, The parameter to be checked.
 * @param[in] : is_check_zero, If to check the parameter is zero.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_general_check_param(uint32_t param, bool is_check_zero)
{
    if (is_check_zero && param == 0) {
        tloge("%s, param=%u\n", __func__, param);
        return SF_MM_ZERO;
    }
    if (!is_block_aligned(param)) {
        tloge("%s, param=%u\n", __func__, param);
        return SF_MM_NOT_BLOCK;
    }
    if (byte_to_block(param) > MAX_ALLOC_COUNT) {
        tloge("%s, param=%u\n", __func__, param);
        return SF_MM_EXCEED_16KB;
    }
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Get the block count of the unit.
 * @param[in] : unit, The uuid_unit.
 * @param[in] : mem_type, The requested memory type, DELETABLE or NON_DELETABLE.
 * @param[out]: unit_cnt, The block count of the unit.
 * @return    : void.
 */
static void secflash_mm_fetch_unit_cnt(struct mng_unit *unit, uint32_t mem_type, uint16_t *unit_cnt)
{
    if (unit_cnt == NULL)
        return;

    if (mem_type == DELETABLE) {
        *unit_cnt = unit->del_cnt;
    } else {
        *unit_cnt = unit->ndel_cnt;
    }
}

/*
 * @brief     : Get the block offset of the unit.
 * @param[in] : unit, The uuid_unit.
 * @param[in] : mem_type, The requested memory type, DELETABLE or NON_DELETABLE.
 * @param[out]: unit_off, The block offset of the unit.
 * @return    : void.
 */
static void secflash_mm_fetch_unit_off(struct mng_unit *unit, uint32_t mem_type, uint16_t *unit_off)
{
    if (unit_off == NULL)
        return;

    if (mem_type == DELETABLE) {
        *unit_off = unit->del_off;
    } else {
        *unit_off = unit->ndel_off;
    }
}

/*
 * @brief     : Find a valid uuid_unit to record the allocation info.
 * @param[in] : mem_type, The requested memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : mng_id, The mng_id information.
 * @param[out]: unit_idx, The valid index in g_uuid_unit.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_alloc_find_unit(uint32_t mem_type, uint8_t mng_id, uint8_t *unit_idx)
{
    int i;
    uint16_t unit_cnt;

    for (i = 0; i < MAX_MNG_UNIT_MUN; i++) {
        if (g_mng_units[i].mng_id == mng_id) {
            secflash_mm_fetch_unit_cnt(&g_mng_units[i], mem_type, &unit_cnt);
            if (unit_cnt != 0) {
                tloge("%s, mng_id=0x%x, type=0x%x, cnt=%u\n", __func__, mng_id, mem_type, unit_cnt);
                return SF_MM_ALLOC_MEM_ALLOCATED;
            }
            *unit_idx = i;
            return SF_MM_SUCCESS;
        }
    }
    for (i = 0; i < MAX_MNG_UNIT_MUN; i++) {
        if (g_mng_units[i].mng_id == MNG_UNIT_INVALID_MNG_ID) {
            *unit_idx = i;
            return SF_MM_SUCCESS;
        }
    }
    return SF_MM_ALLOC_NO_UNIT_AVAILABLE;
}

/*
 * @brief     : Try to find the requested count free meory from deletable space.
 * @param[in] : count, The requested memory block count.
 * @param[in] : bound, The boundary of the free memory spaces.
 * @param[out]: void
 * @return    : The index in g_mem_spaces.
 */
static int secflash_mm_get_del_free_index(uint16_t count, int bound)
{
    int i;

    if (g_share_space_idx >= 0 && g_share_space_idx < bound) {
        for (i = 0; i <= g_share_space_idx; i++) {
            if (g_mem_spaces[i].count >= count)
                return i;
        }
    }
    if (g_division_offset != SECFLASH_MEMORY_END) {
        for (i = 0; i < bound; i++) {
            if (g_mem_spaces[i].offset >= g_division_offset) {
                break;
            }
            if (g_mem_spaces[i].count >= count)
                return i;
        }
    }
    return GENERAL_INVALID_INDEX;
}

/*
 * @brief     : Find the requested count free meory from non-deletable space.
 * @param[in] : count, The requested memory block count.
 * @param[in] : bound, The boundary of the free memory spaces.
 * @param[out]: void
 * @return    : The index in g_mem_spaces.
 */
static int secflash_mm_get_nondel_free_index(uint16_t count, int bound)
{
    int i;

    if (g_share_space_idx >= 0 && g_share_space_idx < bound) {
        for (i = bound - 1; i >= g_share_space_idx; i--) {
            if (g_mem_spaces[i].count >= count)
                return i;
        }
    }
    if (g_division_offset != SECFLASH_MEMORY_END) {
        for (i = bound - 1; i >= 0; i--) {
            if (g_mem_spaces[i].offset + g_mem_spaces[i].count <= g_division_offset) {
                break;
            }
            if (g_mem_spaces[i].count >= count)
                return i;
        }
    }
    return GENERAL_INVALID_INDEX;
}

/*
 * @brief     : Try to find the requested count meory from free space.
 * @param[in] : count, The requested memory block count.
 * @param[in] : mem_type, The requested memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : bound, The boundary of the free memory spaces.
 * @param[out]: void
 * @return    : The index in g_mem_spaces.
 */
static int secflash_mm_get_free_space_index(uint16_t count, uint32_t mem_type, int bound)
{
    if (mem_type == DELETABLE) {
        return secflash_mm_get_del_free_index(count, bound);
    } else {
        return secflash_mm_get_nondel_free_index(count, bound);
    }
}

/*
 * @brief     : Estimate if system information is to be updated after allocation.
 * @param[in] : count, The block count to be allocated.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : index, The free memory space index in g_mem_spaces.
 * @param[out]: sys_off, The system offset to be updated.
 * @param[out]: sys_cnt, The system count to be updated.
 * @return    : Return SYSTEM_TO_UPDATE if system information needs to update, else SYSTEM_NOT_UPDATE.
 */
static uint8_t secflash_mm_alloc_calc_sys_info(uint16_t count, uint32_t mem_type,
    int index, uint16_t *sys_off, uint16_t *sys_cnt)
{
    if (index == g_share_space_idx) {
        if (mem_type == NON_DELETABLE) {
            *sys_off = g_mem_spaces[g_share_space_idx].offset +
                g_mem_spaces[g_share_space_idx].count - count;
            *sys_cnt = SECFLASH_MEMORY_END - *sys_off;
        } else {
            *sys_off = SECFLASH_MNG_MEM_BASE;
            *sys_cnt = g_mem_spaces[g_share_space_idx].offset + count;
        }
        return SYSTEM_TO_UPDATE;
    }
    return SYSTEM_NOT_UPDATE;
}

/*
 * @brief     : Obtain the current system offset.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[out]: old_sys_off, The current system offset.
 * @param[out]: old_sys_cnt, The current system count.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_get_old_sys_info(uint32_t mem_type,
    uint16_t *old_sys_off, uint16_t *old_sys_cnt)
{
    if (g_share_space_idx != GENERAL_INVALID_INDEX) {
        if (mem_type == DELETABLE) {
            *old_sys_off = SECFLASH_MEMORY_BASE;
            *old_sys_cnt = g_mem_spaces[g_share_space_idx].offset - SECFLASH_MEMORY_BASE;
        } else {
            *old_sys_off = g_mem_spaces[g_share_space_idx].offset +
                g_mem_spaces[g_share_space_idx].count;
            *old_sys_cnt = SECFLASH_MEMORY_END - *old_sys_off;
        }
        return SF_MM_SUCCESS;
    }
    if (g_division_offset != SECFLASH_MEMORY_END) {
        if (mem_type == DELETABLE) {
            *old_sys_off = SECFLASH_MEMORY_BASE;
            *old_sys_cnt = g_division_offset - SECFLASH_MEMORY_BASE;
        } else {
            *old_sys_off = g_division_offset;
            *old_sys_cnt = SECFLASH_MEMORY_END - g_division_offset;
        }
        return SF_MM_SUCCESS;
    }
    return SF_MM_FIND_SYS_INFO_FAILED;
}

/*
 * @brief     : Update management data in g_mng_units and g_mem_spaces.
 * @param[in] : count, The block count to allocate.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : uuid_idx, The valid index in g_uuid_white_list.
 * @param[in] : unit_idx, The valid index in g_mng_units.
 * @param[in] : index, The valid index in g_mem_spaces.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_alloc_update_unit(uint16_t count, uint32_t mem_type,
    uint8_t unit_idx, int index)
{
    uint32_t ret;
    uint16_t blk_off;

    if (mem_type == DELETABLE) {
        g_mng_units[unit_idx].del_off = g_mem_spaces[index].offset;
        blk_off = g_mng_units[unit_idx].del_off;
        g_mng_units[unit_idx].del_cnt = count;
        g_mem_spaces[index].offset += count;
    } else {
        g_mng_units[unit_idx].ndel_off = g_mem_spaces[index].offset +
            g_mem_spaces[index].count - count;
        blk_off = g_mng_units[unit_idx].ndel_off;
        g_mng_units[unit_idx].ndel_cnt = count;
    }
    g_mem_spaces[index].count -= count;
    if (g_mem_spaces[index].count == 0) {
        if (index == g_share_space_idx) {
            g_share_space_idx = GENERAL_INVALID_INDEX;
            g_division_offset = g_mem_spaces[index].offset;
        }
        g_mem_spaces[index].offset = 0;
    }

    /* Before allocting to use, erase data. */
    ret = secflash_mm_erase_data(blk_off, count);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_write_mng_data(MNG_DATA_MNG_UNIT, unit_idx);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x\n", __func__, ret);

    return ret;
}

/*
 * @brief     : Before allocation ,backup the current important information.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : is_sys_update, If the system info needs to update.
 * @param[in] : uuid_idx, The valid index in g_uuid_white_list.
 * @param[in] : mng_id, The mng_id to identify a mng_unit.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_alloc_backup(uint32_t mem_type, uint8_t is_sys_update,
    uint8_t unit_idx, uint8_t mng_id)
{
    uint32_t ret;
    uint16_t old_sys_off;
    uint16_t old_sys_cnt;

    /* record the current information, when sudden power-off, rollback */
    g_recovery_info.valid_flag = RECOVERY_INFO_VALID;
    g_recovery_info.op_type = OP_ALLOCATE;
    g_recovery_info.mem_type = mem_type;
    if (mem_type == DELETABLE && g_mng_units[unit_idx].ndel_cnt == 0) {
        mng_id = MNG_UNIT_INVALID_MNG_ID;
    } else if (mem_type == NON_DELETABLE && g_mng_units[unit_idx].del_cnt == 0) {
        mng_id = MNG_UNIT_INVALID_MNG_ID;
    }
    g_recovery_info.mng_id = mng_id;
    g_recovery_info.unit_idx = unit_idx;
    g_recovery_info.unit_off = 0;
    g_recovery_info.unit_cnt = 0;
    g_recovery_info.is_sys_update = is_sys_update;
    if (is_sys_update == SYSTEM_TO_UPDATE) {
        ret = secflash_mm_get_old_sys_info(mem_type, &old_sys_off, &old_sys_cnt);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x\n", __func__, ret);
            return ret;
        }
        g_recovery_info.sys_off = old_sys_off;
        g_recovery_info.sys_cnt = old_sys_cnt;
    }

#ifdef SECFLASH_MM_DEBUG
    tloge("%s\n", __func__);
#endif
    return secflash_mm_write_mng_data(MNG_DATA_RECOVERY_INFO, GENERAL_INVALID_INDEX);
}

/*
 * @brief     : Before allocation ,backup the current important information.
 * @param[in] : count, The block count to allocate.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : mng_id, The mng_id to identify a mng_unit.
 * @param[in] : unit_idx, The valid index in g_mng_units.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_alloc_operation(uint16_t count, uint32_t mem_type, uint8_t mng_id, uint8_t unit_idx)
{
    uint32_t ret;
    int index;
    int bound;
    uint8_t is_sys_update;
    uint16_t sys_off;
    uint16_t sys_cnt;

    bound = secflash_mm_merge_free_space();
    if (bound <= 0) {
        tloge("%s, not enough memory\n", __func__);
        return SF_MM_ALLOC_MEM_NOT_ENOUGH;
    }

    index = secflash_mm_get_free_space_index(count, mem_type, bound);
    if (index == GENERAL_INVALID_INDEX) {
        tloge("%s, no memory anymore\n", __func__);
        return SF_MM_ALLOC_MEM_NOT_ENOUGH;
    }

    sys_off = 0;
    sys_cnt = 0;
    is_sys_update = secflash_mm_alloc_calc_sys_info(count, mem_type, index, &sys_off, &sys_cnt);
    ret = secflash_mm_alloc_backup(mem_type, is_sys_update, unit_idx, mng_id);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    g_mng_units[unit_idx].mng_id = mng_id;
    ret = secflash_mm_alloc_update_unit(count, mem_type, unit_idx, index);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        secflash_mm_reinit();
        return ret;
    }

    ret = secflash_mm_update_system_info(mem_type, is_sys_update, sys_off, sys_cnt);
    if (ret != SF_MM_SUCCESS) {
        secflash_mm_reinit();
        return ret;
    }

    g_recovery_info.valid_flag = RECOVERY_INFO_INVALID;
    ret = secflash_mm_write_mng_data(MNG_DATA_RECOVERY_INFO, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        secflash_mm_reinit();
    }

    return ret;
}

/*
 * @brief     : Check the object info and white list.
 * @param[in] : obj_info, Information contains obj_id and mem_type.
 * @param[out]: uuid_idx, The valid index in g_uuid_white_list.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_entry_check(struct object_info obj_info, uint8_t *uuid_idx)
{
    uint32_t ret;

    if (g_ready_flag != SECFLASH_IS_READY) {
        tloge("%s, not ready, 0x%x! \n", __func__, g_ready_flag);
        return SF_MM_NOT_READY;
    }

    if (obj_info.obj_id > MAX_OBJECT_ID)
        return SF_MM_ALLOC_INVALID_OBJ_ID;

    ret = secflash_mm_check_mem_type(obj_info.mem_type);
    if (ret != SF_MM_SUCCESS)
        return ret;

    ret = secflash_mm_check_uuid(uuid_idx);
    if (ret != SF_MM_SUCCESS)
        return ret;

    return ret;
}

/*
 * @brief     : Try to allocate the requested size of the specific type memory.
 * @param[in] : obj_info, The information of a TA request.
 * @param[in] : size, The requested size of memory.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
uint32_t secflash_mm_alloc(struct object_info obj_info, uint32_t size)
{
    uint32_t ret;
    uint32_t mem_type;
    uint8_t unit_idx;
    uint16_t count;
    uint8_t uuid_idx;
    uint8_t mng_id;
    uint16_t oppo_unit_cnt;

#ifdef SECFLASH_MM_DEBUG
    tloge("Enter %s, count=%u, size=%u, type=0x%x\n", __func__, byte_to_block(size), size, mem_type);
    secflash_mm_print_data();
#endif

    mem_type = obj_info.mem_type;
    ret = secflash_mm_entry_check(obj_info, &uuid_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_general_check_param(size, true);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    count = (uint16_t)byte_to_block(size);
    mng_id = (uint8_t)mng_id_generate(obj_info.obj_id, uuid_idx);
    ret = secflash_mm_alloc_find_unit(mem_type, mng_id, &unit_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    oppo_unit_cnt = (mem_type == DELETABLE) ? g_mng_units[unit_idx].ndel_cnt : g_mng_units[unit_idx].del_cnt;
    if (count > MAX_ALLOC_COUNT - oppo_unit_cnt) {
        tloge("%s, rv=0x%x\n", __func__, SF_MM_EXCEED_16KB);
        return SF_MM_EXCEED_16KB;
    }

    ret = secflash_mm_alloc_operation(count, mem_type, mng_id, unit_idx);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x\n", __func__, ret);

#ifdef SECFLASH_MM_DEBUG
    tloge("Exit %s\n", __func__);
    secflash_mm_print_data();
#endif
    return (uint32_t)ret;
}

/*
 * @brief     : Check if there exists specific allocated memory in g_mng_units.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : mng_id, The mng_id to identify a mng_unit.
 * @param[out]: unit_idx, The unit index in g_mng_units.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_check_mem_exist(uint32_t mem_type, uint8_t mng_id, uint8_t *unit_idx)
{
    int i;
    uint32_t ret;
    uint16_t unit_cnt;

    for (i = 0; i < MAX_MNG_UNIT_MUN; i++) {
        if (mng_id == g_mng_units[i].mng_id) {
                secflash_mm_fetch_unit_cnt(&g_mng_units[i], mem_type, &unit_cnt);
                if (unit_cnt == 0) {
                    ret = SF_MM_MEMORY_NOT_ALLOCATED;
                    tloge("%s, rv=0x%x, type=0x%x, del=%u, ndel=%u\n", __func__, ret, mem_type, \
                        g_mng_units[i].del_cnt, g_mng_units[i].ndel_cnt);
                    return ret;
                } else {
                    *unit_idx = i;
                    return SF_MM_SUCCESS;
                }
            }
    }
    return SF_MM_MEMORY_NOT_ALLOCATED;
}

/*
 * @brief     : Estimate if the system information is to be updated after free.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : unit_idx, The unit index in g_mng_units.
 * @param[out]: sys_off, The system offset to be updated.
 * @param[out]: sys_cnt, The system count to be updated.
 * @return    : Return SYSTEM_TO_UPDATE if system information needs to update, else SYSTEM_NOT_UPDATE.
 */
static uint8_t secflash_mm_free_calc_sys_info(uint32_t mem_type, int unit_idx,
    uint16_t *sys_off, uint16_t *sys_cnt)
{
    uint16_t comp_off = SECFLASH_MEMORY_END;

    if (g_share_space_idx != GENERAL_INVALID_INDEX) {
        if (mem_type == DELETABLE) {
            comp_off = g_mem_spaces[g_share_space_idx].offset;
        } else {
            comp_off = g_mem_spaces[g_share_space_idx].offset +
                g_mem_spaces[g_share_space_idx].count;
        }
    }
    if (g_division_offset != SECFLASH_MEMORY_END)
        comp_off = g_division_offset;

    if (comp_off <= SECFLASH_MNG_MEM_END) {
        if (mem_type == DELETABLE) {
            if (g_mng_units[unit_idx].del_off +
                g_mng_units[unit_idx].del_cnt == comp_off) {
                *sys_off = SECFLASH_MEMORY_BASE;
                *sys_cnt = g_mng_units[unit_idx].del_off - SECFLASH_MEMORY_BASE;
                return SYSTEM_TO_UPDATE;
            }
        } else {
            if (g_mng_units[unit_idx].ndel_off == comp_off) {
                *sys_off = g_mng_units[unit_idx].ndel_off + g_mng_units[unit_idx].ndel_cnt;
                *sys_cnt = SECFLASH_MEMORY_END - *sys_off;
                return SYSTEM_TO_UPDATE;
            }
        }
    }

    return SYSTEM_NOT_UPDATE;
}

/*
 * @brief     : Try to merge the free memory to a mem_space in g_mem_spaces.
 * @param[in] : offset, The offset of the free memory.
 * @param[in] : count, The block count of the free memory.
 * @param[out]: void
 * @return    : Return the index in g_mem_spaces.
 */
static int secflash_mm_free_add_space_try_merge(uint16_t offset, uint16_t count)
{
    int i;

    /* If the space to be freed is adjacent to some free space, merge them. */
    for (i = 0; i < MEM_SPACE_NUM; i++) {
        if (g_mem_spaces[i].offset + g_mem_spaces[i].count == offset) {
            g_mem_spaces[i].count += count;
            return i;;
        } else if (offset + count == g_mem_spaces[i].offset) {
            g_mem_spaces[i].offset = offset;
            g_mem_spaces[i].count += count;
            return i;
        }
    }
    return GENERAL_INVALID_INDEX;
}

/*
 * @brief     : Try to add the free memory to a new mem_space in g_mem_spaces.
 * @param[in] : offset, The offset of the free memory.
 * @param[in] : count, The block count of the free memory.
 * @param[out]: void
 * @return    : Return the index in g_mem_spaces.
 */
static int secflash_mm_free_add_space_new(uint16_t offset, uint16_t count)
{
    int i;

    /* Find a non-used mem space to denote the new free space. */
    for (i = 0; i < MEM_SPACE_NUM; i++) {
        if (g_mem_spaces[i].count == 0) {
            g_mem_spaces[i].offset = offset;
            g_mem_spaces[i].count = count;
            return i;
        }
    }
    return GENERAL_INVALID_INDEX;
}

/*
 * @brief     : Add a free memory to the g_mem_spaces for further management.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : offset, The offset of the free memory.
 * @param[in] : count, The block count of the free memory.
 * @param[out]: void
 * @return    : Return true if the free memory has been managed, else false.
 */
static bool secflash_mm_free_add_space(uint32_t mem_type, uint16_t offset, uint16_t count)
{
    int index;

    index = secflash_mm_free_add_space_try_merge(offset, count);
    if (index == GENERAL_INVALID_INDEX)
        index = secflash_mm_free_add_space_new(offset, count);

    if (index == GENERAL_INVALID_INDEX)
        return false;

    /* If the newly free space is adjacent to division boundary.
     * Mark this free space to be the shared memory. */
    if ((mem_type == DELETABLE && (offset + count) == g_division_offset) ||
        (mem_type == NON_DELETABLE && offset == g_division_offset)) {
        g_share_space_idx = index;
        g_division_offset = SECFLASH_MEMORY_END;
    }
    return true;
}

/*
 * @brief     : Change the mng_unit management data.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : unit_idx, The index in g_mng_units.
 * @param[out]: void
 * @return    : void
 */
static void secflash_mm_free_reset_unit(uint32_t mem_type, int unit_idx)
{
    if (mem_type == DELETABLE) {
        g_mng_units[unit_idx].del_off = 0;
        g_mng_units[unit_idx].del_cnt = 0;
        /* If NON_DELETABLE info is none, recycle this uuid_unit. */
        if (g_mng_units[unit_idx].ndel_cnt == 0) {
            g_mng_units[unit_idx].ndel_off = 0;
            g_mng_units[unit_idx].mng_id = MNG_UNIT_INVALID_MNG_ID;
        }
    } else {
        g_mng_units[unit_idx].ndel_off = 0;
        g_mng_units[unit_idx].ndel_cnt = 0;
        /* If DELETABLE info is none, recycle this uuid_unit. */
        if (g_mng_units[unit_idx].del_cnt == 0) {
            g_mng_units[unit_idx].del_off = 0;
            g_mng_units[unit_idx].mng_id = MNG_UNIT_INVALID_MNG_ID;
        }
    }
}

/*
 * @brief     : Before free ,backup the current important information.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : is_sys_update, If the system info needs to update.
 * @param[in] : unit_idx, The valid index in g_mng_units.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_free_backup(uint32_t mem_type, uint8_t is_sys_update, uint8_t unit_idx)
{
    uint32_t ret;
    uint16_t old_sys_off;
    uint16_t old_sys_cnt;

    /* Record the current information, when sudden power-off, rollback */
    g_recovery_info.valid_flag = RECOVERY_INFO_VALID;
    g_recovery_info.op_type = OP_FREE;
    g_recovery_info.mem_type = mem_type;
    g_recovery_info.mng_id = g_mng_units[unit_idx].mng_id;
    g_recovery_info.unit_idx = unit_idx;
    if (mem_type == DELETABLE) {
        g_recovery_info.unit_off = g_mng_units[unit_idx].del_off;
        g_recovery_info.unit_cnt = g_mng_units[unit_idx].del_cnt;
    } else {
        g_recovery_info.unit_off = g_mng_units[unit_idx].ndel_off;
        g_recovery_info.unit_cnt = g_mng_units[unit_idx].ndel_cnt;
    }
    g_recovery_info.is_sys_update = is_sys_update;
    if (is_sys_update == SYSTEM_TO_UPDATE) {
        ret = secflash_mm_get_old_sys_info(mem_type, &old_sys_off, &old_sys_cnt);
        if (ret != SF_MM_SUCCESS) {
            tloge("%s, rv=0x%x\n", __func__, ret);
            return ret;
        }
        g_recovery_info.sys_off = old_sys_off;
        g_recovery_info.sys_cnt = old_sys_cnt;
    }

    return secflash_mm_write_mng_data(MNG_DATA_RECOVERY_INFO, GENERAL_INVALID_INDEX);
}

/*
 * @brief     :  To update data of the free operation.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : unit_idx, The valid index in g_mng_units.
 * @param[in] : is_sys_update, If the system information need to be updated.
 * @param[in] : sys_off, The new offset system info to be updated.
 * @param[in] : sys_cnt, The new count system info to be updated.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_free_update_data(uint32_t mem_type, uint8_t unit_idx,
    uint8_t is_sys_update, uint16_t sys_off, uint16_t sys_cnt)
{
    uint32_t ret;
    uint16_t old_unit_off;
    uint16_t old_unit_cnt;
    bool is_free_added = false;

    secflash_mm_fetch_unit_off(&g_mng_units[unit_idx], mem_type, &old_unit_off);
    secflash_mm_fetch_unit_cnt(&g_mng_units[unit_idx], mem_type, &old_unit_cnt);

    /* Reset the mng_unit's allocated information. */
    secflash_mm_free_reset_unit(mem_type, unit_idx);

    ret = secflash_mm_write_mng_data(MNG_DATA_MNG_UNIT, unit_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    /* Add the released space to the free mem space pool. */
    is_free_added = secflash_mm_free_add_space(mem_type, old_unit_off, old_unit_cnt);
    if (!is_free_added) {
        ret = SF_MM_FREE_NO_MEM_SPACE;
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_update_system_info(mem_type, is_sys_update, sys_off, sys_cnt);
    if (ret != SF_MM_SUCCESS) {
        return ret;
    }

    g_recovery_info.valid_flag = RECOVERY_INFO_INVALID;
    ret = secflash_mm_write_mng_data(MNG_DATA_RECOVERY_INFO, GENERAL_INVALID_INDEX);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x\n", __func__, ret);

    return ret;
}

/*
 * @brief     : The core operation of the free.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : unit_idx, The valid index in g_uuid_units.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
static uint32_t secflash_mm_free_operation(uint32_t mem_type, uint8_t unit_idx)
{
    uint32_t ret;
    uint16_t sys_off;
    uint16_t sys_cnt;
    uint8_t is_sys_update;

    sys_off = 0;
    sys_cnt = 0;
    is_sys_update = secflash_mm_free_calc_sys_info(mem_type, unit_idx, &sys_off, &sys_cnt);
    ret = secflash_mm_free_backup(mem_type, is_sys_update, unit_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    ret = secflash_mm_free_update_data(mem_type, unit_idx, is_sys_update, sys_off, sys_cnt);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        secflash_mm_reinit();
    }
    return ret;
}

/*
 * @brief     : Try to free the specific type allocated memory.
 * @param[in] : obj_info, The information of a TA request.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
uint32_t secflash_mm_free(struct object_info obj_info)
{
    uint32_t ret;
    uint8_t uuid_idx;
    uint8_t unit_idx;

#ifdef SECFLASH_MM_DEBUG
    tloge("Enter %s, mem_type=0x%x\n", __func__, obj_info.mem_type);
    secflash_mm_print_data();
#endif

    ret = secflash_mm_entry_check(obj_info, &uuid_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_check_mem_exist(obj_info.mem_type, (uint8_t)mng_id_generate(obj_info.obj_id, uuid_idx),
        &unit_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }
    ret = secflash_mm_free_operation(obj_info.mem_type, unit_idx);

#ifdef SECFLASH_MM_DEBUG
    tloge("Exit %s\n", __func__);
    secflash_mm_print_data();
#endif

    return ret;
}

/*
 * @brief     : Try to fecth the block offset and count of the unit.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : uuid_idx, The valid index in g_uuid_white_list.
 * @param[out]: unit_off, The block offset of the unit.
 * @param[out]: unit_cnt, The block offset of the unit.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_fetch_unit_info(uint32_t mem_type, uint8_t mng_id,
    uint16_t *unit_off, uint16_t *unit_cnt)
{
    uint32_t ret;
    uint8_t unit_idx;

    ret = secflash_mm_check_mem_exist(mem_type, mng_id, &unit_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    secflash_mm_fetch_unit_off(&g_mng_units[unit_idx], mem_type, unit_off);
    secflash_mm_fetch_unit_cnt(&g_mng_units[unit_idx], mem_type, unit_cnt);
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Try to select the specific allocated memory.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[out]: size, The allocated space size.
 * @return    : Operation status: success(0) or other failure status
 */
uint32_t secflash_mm_select(struct object_info obj_info, uint32_t *size)
{
    uint32_t ret;
    uint32_t obj_id;
    uint32_t mem_type;
    uint8_t uuid_idx;
    uint8_t mng_id;
    uint16_t unit_cnt;

#ifdef SECFLASH_MM_DEBUG
    tloge("Enter %s\n", __func__);
    secflash_mm_print_data();
#endif

    ret = secflash_mm_entry_check(obj_info, &uuid_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    obj_id = obj_info.obj_id;
    mem_type = obj_info.mem_type;
    if (size == NULL) {
        ret = SF_MM_NULL_POINTER;
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    mng_id = (uint8_t)mng_id_generate(obj_id, uuid_idx);
    unit_cnt = 0;
    ret = secflash_mm_fetch_unit_info(mem_type, mng_id, NULL, &unit_cnt);
    if (ret != SF_MM_SUCCESS) {
        return ret;
    }

    *size = block_to_byte(unit_cnt);
#ifdef SECFLASH_MM_DEBUG
    tloge("Exit %s\n", __func__);
    secflash_mm_print_data();
#endif
    return (uint32_t)SF_MM_SUCCESS;
}

/*
 * @brief     : Change the current position of the specific allocated memory.
 * @param[in] : pos, Pointer pointing to the current position.
 * @param[in] : offset, The value to be used for changing the position.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_set_param_check(uint32_t *pos, int32_t offset)
{
    uint32_t ret;

    if (pos == NULL) {
        tloge("%s, rv=0x%x\n", __func__, SF_MM_SEEK_NULL_POINTER);
        return SF_MM_SEEK_NULL_POINTER;
    }
    ret = secflash_mm_general_check_param(*pos, false);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    if (offset < 0) {
        ret = secflash_mm_general_check_param(-offset, false);
    } else {
        ret = secflash_mm_general_check_param(offset, false);
    }
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x\n", __func__, ret);

    return ret;
}

/*
 * @brief     : Check TEE_DATA_SEEK_SET parameter if valid.
 * @param[in] : blk_pos, The current position of the allocated memory.
 * @param[in] : blk_off, The value to be used for changing the position.
 * @param[in] : unit_cnt, The allocated memory space size.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_seek_set_check(int16_t blk_off, uint16_t unit_cnt)
{
    uint32_t ret;

    ret = SF_MM_SUCCESS;
    if (blk_off < 0) {
        ret = SF_MM_SEEK_SET_NEGATIVE;
    } else if (blk_off > unit_cnt) {
        ret = SF_MM_SEEK_SET_EXCEED_ROOF;
    }
    return ret;
}

/*
 * @brief     : Check TEE_DATA_SEEK_CUR parameter if valid.
 * @param[in] : blk_pos, The current position of the allocated memory.
 * @param[in] : blk_off, The value to be used for changing the position.
 * @param[in] : unit_cnt, The allocated memory space size.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_seek_cur_check(uint16_t blk_pos, int16_t blk_off,
    uint16_t unit_cnt)
{
    uint32_t ret;
    uint16_t abs_off;

    ret = SF_MM_SUCCESS;
    abs_off = blk_off > 0 ? (uint16_t)blk_off : ((uint16_t)(-blk_off));
    if (blk_off > unit_cnt || unit_cnt - blk_pos < blk_off)
        ret = SF_MM_SEEK_CUR_EXCEED_ROOF;

    if (blk_off < 0 && abs_off > blk_pos)
        ret = SF_MM_SEEK_CUR_EXCEED_FLOOR;
    return ret;
}

/*
 * @brief     : Check TEE_DATA_SEEK_END parameter if valid.
 * @param[in] : blk_pos, The current position of the allocated memory.
 * @param[in] : blk_off, The value to be used for changing the position.
 * @param[in] : unit_cnt, The allocated memory space size.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_seek_end_check(int16_t blk_off, uint16_t unit_cnt)
{
    uint32_t ret;
    uint16_t abs_off;

    ret = SF_MM_SUCCESS;
    abs_off = blk_off > 0 ? (uint16_t)blk_off : ((uint16_t)(-blk_off));
    if (blk_off > 0)
        ret = SF_MM_SEEK_END_POSITIVE;

    if (abs_off > unit_cnt)
        ret = SF_MM_SEEK_END_EXCEED_FLOOR;

    return ret;
}

/*
 * @brief     : Before changing position, check parameter if valid.
 * @param[in] : blk_pos, The current position of the allocated memory.
 * @param[in] : blk_off, The value to be used for changing the position.
 * @param[in] : unit_cnt, The allocated memory space size.
 * @param[in] : whence, The postion changing way.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_set_whence_check(uint16_t blk_pos, int16_t blk_off,
    uint16_t unit_cnt, TEE_Whence whence)
{
    uint32_t ret;

    switch (whence) {
    case TEE_DATA_SEEK_SET:
        ret = secflash_mm_seek_set_check(blk_off, unit_cnt);
        break;
    case TEE_DATA_SEEK_CUR:
        ret = secflash_mm_seek_cur_check(blk_pos, blk_off, unit_cnt);
        break;
    case TEE_DATA_SEEK_END:
        ret = secflash_mm_seek_end_check(blk_off, unit_cnt);
        break;
    default:
        ret = SF_MM_SEEK_INVALID_WHENCE;
        break;
    }
    return ret;
}

/*
 * @brief     : Change block position by whence.
 * @param[in] : blk_pos, The current block position.
 * @param[in] : blk_off, The value to be used for changing the position.
 * @param[in] : unit_cnt, The memory total block count.
 * @param[in] : whence, The postion changing way.
 * @return    : Newly block position.
 */
static uint16_t secflash_mm_set_operation(uint16_t blk_pos, int16_t blk_off, uint16_t unit_cnt,
    TEE_Whence whence)
{
    switch (whence) {
    case TEE_DATA_SEEK_SET:
        blk_pos = (uint16_t)blk_off;
        break;
    case TEE_DATA_SEEK_CUR:
        if (blk_off > 0) {
            blk_pos = blk_pos + blk_off;
        } else {
            blk_pos = blk_pos - (uint16_t)(-blk_off);
        }
        break;
    case TEE_DATA_SEEK_END:
        blk_pos = unit_cnt - (uint16_t)(-blk_off);
        break;
    default:
        break;
    }

    return blk_pos;
}

/*
 * @brief     : Change the current position of the specific allocated memory.
 * @param[in] : obj_info, The information of a TA request.
 * @param[in] : pos, The current position of the allocated memory.
 * @param[in] : offset, The value to be used for changing the position.
 * @param[in] : whence, The postion changing way.
 * @param[out]: pos, The changed position
 * @return    : Operation status: success(0) or other failure status
 */
uint32_t secflash_mm_set_offset(struct object_info obj_info, uint32_t *pos, int32_t offset, TEE_Whence whence)
{
    uint32_t ret;
    uint8_t uuid_idx;
    uint8_t mng_id;
    uint16_t blk_pos;
    int16_t blk_off;
    uint16_t unit_cnt;

#ifdef SECFLASH_MM_DEBUG
    tloge("Enter %s\n", __func__);
    secflash_mm_print_data();
#endif

    ret = secflash_mm_entry_check(obj_info, &uuid_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_set_param_check(pos, offset);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    blk_pos = byte_to_block(*pos);
    blk_off = byte_to_block(offset);

    mng_id = (uint8_t)mng_id_generate(obj_info.obj_id, uuid_idx);
    unit_cnt = 0;
    ret = secflash_mm_fetch_unit_info(obj_info.mem_type, mng_id, NULL, &unit_cnt);
    if (ret != SF_MM_SUCCESS) {
        return (uint32_t)ret;
    }

    ret = secflash_mm_set_whence_check(blk_pos, blk_off, unit_cnt, whence);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x, pos=%u, off=%d, cnt=%u, whence=%u\n", __func__, ret, blk_pos, blk_off, \
            unit_cnt, whence);
        return (uint32_t)ret;
    }

    blk_pos = secflash_mm_set_operation(blk_pos, blk_off, unit_cnt, whence);
    *pos = block_to_byte(blk_pos);

#ifdef SECFLASH_MM_DEBUG
    tloge("Exit %s\n", __func__);
    secflash_mm_print_data();
#endif
    return (uint32_t)SF_MM_SUCCESS;
}

/*
 * @brief     : Before read data, check the parameter.
 * @param[in] : pos, The current position of the allocated memory.
 * @param[in] : size, The size of data to read.
 * @param[in] : buffer, Pointer.
 * @param[in] : count, Pointer.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_read_param_check(uint32_t pos, uint32_t size,
    uint8_t *buffer, uint32_t *count)
{
    uint32_t ret;
    uint16_t blk_cnt;

    ret = SF_MM_SUCCESS;

    ret = secflash_mm_general_check_param(pos, false);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_general_check_param(size, true);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    blk_cnt = byte_to_block(size);

    if (blk_cnt > MAX_READ_COUNT && blk_cnt != MAX_READ_SPECIAL_COUNT) {
        ret = SF_MM_READ_SIZE_EXCEED_ROOF;
        tloge("%s, rv=0x%x, size=%u\n", __func__, ret, size);
        return ret;
    }
    if (buffer == NULL) {
        ret = SF_MM_READ_BUF_NULL;
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    if (count == NULL) {
        ret = SF_MM_READ_RET_NULL;
        tloge("%s, rv=0x%x\n", __func__, ret);
    }
    return ret;
}

/*
 * @brief     : Try check the input unit information.
 * @param[in] : is_read, If this operation is read.
 * @param[in] : mem_type, The memory type, DELETABLE or NON_DELETABLE.
 * @param[in] : uuid_idx, The valid index in g_uuid_white_list.
 * @param[in] : info, The information to be checked.
 * @param[out]: info, Return the actually information.
 * @param[out]: unit_info, Return the unit information.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_check_unit_info(bool is_read, uint32_t mem_type,
    uint8_t uuid_idx, struct mem_space *info, struct mem_space *unit_info)
{
    uint32_t ret;
    uint16_t blk_off;
    uint16_t blk_cnt;
    uint16_t unit_cnt;
    uint16_t unit_off;

    blk_off = info->offset;
    blk_cnt = info->count;
    unit_cnt = 0;
    ret = secflash_mm_fetch_unit_info(mem_type, uuid_idx, &unit_off, &unit_cnt);
    if (ret != SF_MM_SUCCESS) {
        return ret;
    }

    if (blk_cnt > unit_cnt) {
        ret = SF_MM_RW_EXCEED_ROOF;
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    if (blk_off >= unit_cnt) {
        ret = SF_MM_RW_END;
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    } else if (blk_cnt > unit_cnt - blk_off) {
        if (is_read == true) {
            blk_cnt = unit_cnt - blk_off;
        } else {
            return SF_MM_WRITE_SIZE_EXCEED_ROOF;
        }
    }
    info->offset = blk_off;
    info->count = blk_cnt;

    unit_info->offset = unit_off;
    unit_info->count = unit_cnt;
    return SF_MM_SUCCESS;
}

/*
 * @brief     : Try to read data from the specific allocated memory.
 * @param[in] : obj_info, The information of a TA request.
 * @param[in] : pos, The current position of the allocated memory.
 * @param[in] : size, The size of data to read.
 * @param[out]: buffer, The buffer to contain the read data.
 * @param[out]: count, Return the actually read data size.
 * @return    : Operation status: success(0) or other failure status
 */
uint32_t secflash_mm_read(struct object_info obj_info, uint32_t pos, uint32_t size, uint8_t *buffer, uint32_t *count)
{
    uint32_t ret;
    uint8_t uuid_idx;
    struct mem_space input_info;
    struct mem_space unit_info;

    ret = secflash_mm_entry_check(obj_info, &uuid_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_read_param_check(pos, size, buffer, count);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    input_info.offset = byte_to_block(pos);
    input_info.count = byte_to_block(size);
    ret = secflash_mm_check_unit_info(true, obj_info.mem_type, (uint8_t)mng_id_generate(obj_info.obj_id, uuid_idx),
        &input_info, &unit_info);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_read_blocks(SECFLASH_SECURE_STORAGE_TYPE, unit_info.offset + input_info.offset,
        input_info.count, buffer, size);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x, off=%u, cnt=%u\n", __func__, ret, unit_info.offset + input_info.offset,\
            input_info.count);
        return (uint32_t)ret;
    }

    *count = block_to_byte(input_info.count);
    return (uint32_t)SF_MM_SUCCESS;
}

/*
 * @brief     : Before write data, check the parameter.
 * @param[in] : pos, The current position of the allocated memory.
 * @param[in] : size, The size of data to write.
 * @param[in] : buffer, Pointer.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
static uint32_t secflash_mm_write_param_check(uint32_t pos, uint32_t size, uint8_t *buffer)
{
    uint32_t ret;
    uint16_t blk_cnt;

    ret = secflash_mm_general_check_param(pos, false);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    ret = secflash_mm_general_check_param(size, true);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }
    blk_cnt = byte_to_block(size);

    if (blk_cnt > MAX_WRITE_COUNT) {
        ret = SF_MM_WRITE_SIZE_EXCEED_ROOF;
        tloge("%s, rv=0x%x, size=%u\n", __func__, ret, size);
        return ret;
    }

    if (buffer == NULL) {
        ret = SF_MM_WRITE_BUF_NULL;
        tloge("%s, rv=0x%x\n", __func__, ret);
    }
    return ret;
}


/*
 * @brief     : Try to write data into the specific allocated memory.
 * @param[in] : obj_info, The information of a TA request.
 * @param[in] : pos, The current position of the allocated memory.
 * @param[in] : size, The size of data to write.
 * @param[in] : buffer, The buffer containing data to write.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
uint32_t secflash_mm_write(struct object_info obj_info, uint32_t pos, uint32_t size, uint8_t *buffer)
{
    uint32_t ret;
    uint8_t uuid_idx;
    struct mem_space input_info;
    struct mem_space unit_info;

    ret = secflash_mm_entry_check(obj_info, &uuid_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_mm_write_param_check(pos, size, buffer);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    input_info.offset = byte_to_block(pos);
    input_info.count = byte_to_block(size);
    ret = secflash_mm_check_unit_info(false, obj_info.mem_type, (uint8_t)mng_id_generate(obj_info.obj_id, uuid_idx),
        &input_info, &unit_info);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_write_blocks(SECFLASH_SECURE_STORAGE_TYPE, unit_info.offset + input_info.offset,
        input_info.count, buffer);
    if (ret != SF_MM_SUCCESS)
        tloge("%s, rv=0x%x, w_off=%u, w_cnt=%u\n", __func__, ret, unit_info.offset + input_info.offset, \
        input_info.count);

    return (uint32_t)ret;
}

/*
 * @brief     : Get the current position and size of allocated memory.
 * @param[in] : obj_info, The information of a TA request.
 * @param[in] : cur_pos, The current position of the allocated memory.
 * @param[out]: pos, Set to the valid current position.
 * @param[out]: len, Set to be the size of the allocated memory.
 * @return    : Operation status: success(0) or other failure status
 */
uint32_t secflash_mm_get_info(struct object_info obj_info, uint32_t cur_pos, uint32_t *pos, uint32_t *len)
{
    uint32_t ret;
    uint8_t uuid_idx;
    uint8_t mng_id;
    uint16_t blk_off;
    uint16_t unit_cnt;

#ifdef SECFLASH_MM_DEBUG
    tloge("Enter %s\n", __func__);
    secflash_mm_print_data();
#endif

    ret = secflash_mm_entry_check(obj_info, &uuid_idx);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return ret;
    }

    if (pos == NULL || len == NULL) {
        ret = SF_MM_GET_INFO_PARAM_NULL;
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    ret = secflash_mm_general_check_param(cur_pos, false);
    if (ret != SF_MM_SUCCESS) {
        tloge("%s, rv=0x%x\n", __func__, ret);
        return (uint32_t)ret;
    }

    blk_off = byte_to_block(cur_pos);
    mng_id = (uint8_t)mng_id_generate(obj_info.obj_id, uuid_idx);
    unit_cnt = 0;
    ret = secflash_mm_fetch_unit_info(obj_info.mem_type, mng_id, NULL, &unit_cnt);
    if (ret != SF_MM_SUCCESS) {
        return (uint32_t)ret;
    }

    if (blk_off > unit_cnt) {
        ret = SF_MM_GET_INFO_ORI_POS_EXCEED_ROOF;
        tloge("%s, rv=0x%x, off=%u, u_cnt=%u\n", __func__, ret, blk_off, unit_cnt);
        return (uint32_t)ret;
    }

    *pos = block_to_byte(blk_off);
    *len = block_to_byte(unit_cnt);

#ifdef SECFLASH_MM_DEBUG
    tloge("Exit %s\n", __func__);
    secflash_mm_print_data();
#endif
    return (uint32_t)SF_MM_SUCCESS;
}

/*
 * @brief     : Set the current TEE_UUID.
 * @param[in] : cur_uuid, The current TEE_UUID.
 * @param[out]: void
 * @return    : void
 */
void secflash_mm_set_current_uuid(TEE_UUID *cur_uuid)
{
    if (g_ready_flag != SECFLASH_IS_READY) {
        tloge("%s, not ready, 0x%x! \n", __func__, g_ready_flag);
        return;
    }
    g_current_uuid = cur_uuid;
}
