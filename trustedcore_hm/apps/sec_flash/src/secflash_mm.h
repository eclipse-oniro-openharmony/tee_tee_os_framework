/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash memory management.
 * Author: chengruhong
 * Create: 2019-08-27
 * Notes:
 * History: 2019-08-27 chengruhong create
 */
#ifndef __SECFLASH_MM_H__
#define __SECFLASH_MM_H__

#include <stdint.h>
#include "tee_trusted_storage_api.h"

enum sf_mm_status {
    SF_MM_SUCCESS = 0x0,             /** secflash success */
    SF_MM_INVALID_UUID = 0x85000001, /** secflash uuid not in whitelist */
    SF_MM_INVALID_MEM_TYPE = 0x85000002, /** not supported memory type */
    SF_MM_ZERO = 0x85000003, /** secflash value is zero */
    SF_MM_NOT_BLOCK = 0x85000004, /** secflash value is not block aligned */
    SF_MM_EXCEED_16KB = 0x85000005, /** secflash value exceed 16KB */
    SF_MM_FIND_SYS_INFO_FAILED = 0x85000006, /** secflash cannot find the system information */
    SF_MM_MEMORY_NOT_ALLOCATED = 0x85000007, /* secflash memory has not been allocated */
    SF_MM_MEMCPY_FAIL = 0x8500000A, /* secflash memcpy_s fail */
    SF_MM_MEMSET_FAIL = 0x8500000C, /* secflash memset_s fail */
    SF_MM_INVALID_MNG_DATA = 0x8500000D, /* secflash invalid management data type */
    SF_MM_NULL_POINTER = 0x8500000F, /** secflash null pointer */
    SF_MM_NOT_READY = 0x85000010, /** secflash not ready to support service for out calling */
    SF_MM_UPGRADE_FAIL = 0x85000011, /** secflash upgrade fail */
    SF_MM_INIT_SPACE_OVERLAP = 0x85000201, /** secflash memory space overlapped */
    SF_MM_INIT_EXCEED_ROOF = 0x85000202, /** secflash size is too big */
    SF_MM_INIT_NO_MEM_SPACE = 0x85000203, /** secflash no more mem_space */
    SF_MM_INIT_FACTORY_STATUS_NOT_KNOWN = 0x85000204, /** secflash not known factory status */
    SF_MM_RECOVER_INVALID_OP_TYPE = 0x85000301, /* secflash unrecognized op type */
    SF_MM_RECOVER_INVALID_UUID_IDX = 0x85000302, /* secflash unrecognized op type */
    SF_MM_RECOVER_INVALID_UNIT_IDX = 0x85000303, /* secflash unrecognized op type */
    SF_MM_ALLOC_MEM_NOT_ENOUGH = 0x85000501, /** secflash not enough memory to alloc */
    SF_MM_ALLOC_MEM_ALLOCATED = 0x85000502, /** secflash memory already allocated */
    SF_MM_ALLOC_NO_UNIT_AVAILABLE = 0x85000504, /** secflash no available unit */
    SF_MM_ALLOC_INVALID_OBJ_ID = 0x85000505, /** secflash invalid object_id */
    SF_MM_FREE_NO_MEM_SPACE = 0x85000602, /** secflash uuid has no mem space to denote the free memory */
    SF_MM_SEEK_NULL_POINTER = 0x85000701, /** secflash seek parameter null poiter */
    SF_MM_SEEK_INVALID_WHENCE = 0x85000703, /** secflash seek invalid whence param */
    SF_MM_SEEK_SET_NEGATIVE = 0x85000711, /** secflash seek offset is negative */
    SF_MM_SEEK_SET_EXCEED_ROOF = 0x85000712, /** secflash seek offset exceed the origin size */
    SF_MM_SEEK_CUR_EXCEED_ROOF = 0x85000721, /** secflash seek offset exceed the origin size */
    SF_MM_SEEK_CUR_EXCEED_FLOOR = 0x85000722, /** secflash seek offset exceed the origin size */
    SF_MM_SEEK_END_POSITIVE = 0x85000731, /** secflash seek offset is positive */
    SF_MM_SEEK_END_EXCEED_FLOOR = 0x85000732, /** secflash seek offset exceed the origin size */
    SF_MM_READ_SIZE_EXCEED_ROOF = 0x85000801, /** secflash read size too big */
    SF_MM_READ_BUF_NULL = 0x85000802, /** secflash read parameter buffer is null */
    SF_MM_READ_RET_NULL = 0x85000803, /** secflash read parameter return pointer is null */
    SF_MM_READ_END = 0x85000804, /** secflash read the end of the memory */
    SF_MM_WRITE_SIZE_EXCEED_ROOF = 0x85000901, /** secflash write size it too big  */
    SF_MM_WRITE_BUF_NULL = 0x85000902, /** secflash write param buffer is null */
    SF_MM_WRITE_END = 0x85000903, /** secflash read the end of the memory */
    SF_MM_GET_INFO_PARAM_NULL = 0x85000A01, /** secflash get info parameter is null */
    SF_MM_GET_INFO_ORI_POS_EXCEED_ROOF = 0x85000A02, /** secflash input position exceeds the size */
    SF_MM_RW_END = 0x85000B01, /** secflash read or write the end of the memory */
    SF_MM_RW_EXCEED_ROOF = 0x85000B02, /** secflash read or write size too big */
};

/* The information of a TA request. */
struct object_info {
    /* The same TA use obj_id to distinguish different object. */
    uint32_t obj_id;
    /* A object with the same TA and the same obj_id can apply different memory type. */
    uint32_t mem_type;
};

void secflash_mm_init(uint32_t state);

uint32_t secflash_mm_alloc(struct object_info obj_info, uint32_t size);

uint32_t secflash_mm_free(struct object_info obj_info);

uint32_t secflash_mm_select(struct object_info obj_info, uint32_t *size);

uint32_t secflash_mm_set_offset(struct object_info obj_info, uint32_t *pos, int32_t offset, TEE_Whence whence);

uint32_t secflash_mm_read(struct object_info obj_info, uint32_t pos, uint32_t size, uint8_t *buffer, uint32_t *count);

uint32_t secflash_mm_write(struct object_info obj_info, uint32_t pos, uint32_t size, uint8_t *buffer);

uint32_t secflash_mm_get_info(struct object_info obj_info, uint32_t cur_pos, uint32_t *pos, uint32_t *len);

void secflash_mm_set_current_uuid(TEE_UUID *cur_uuid);
#endif /* __SECFLASH_MM_H__ */