/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file contains the public declaration for HWSDP
 * Author: Huzhonghua h00440650
 * Create: 2020-10-19
 */

#ifndef HWSDP_TA_UTILS_H
#define HWSDP_TA_UTILS_H

#include <stdint.h>
#include "tee_defines.h"

#define HWSDP_DATA_MAX_LENGTH 512
#define BITMAP_MAX_INDEX 32
#define MAX_USER_NUMBER 8

#define HWSDP_GET_4BYTE(var, buf, offset) do { \
    (var) = *(uint32_t *)((uint8_t *)(buf) + (offset)); \
    (offset) += (uint32_t)sizeof(uint32_t); \
} while (0)

/*
 * if len > HWSDP_DATA_MAX_LENGTH, data buffer(mPtr) allowed and caches the data; 
 * else, data cached in the byte array(buf).
 */
typedef struct {
    union {
        uint8_t buf[HWSDP_DATA_MAX_LENGTH]; /* data context */
        uint8_t *mem_ptr; /* pointer of the data */
    } data;
    uint32_t len; /* data length */
} hwsdp_data_info;

typedef struct {
    int32_t op_code; /* tee operate code */
    uint32_t length; /* tee process data */
} hwsdp_msghdr;

/* function type of hwsdp message handler */
typedef int32_t (*hwsdp_msghandler)(uint32_t param_types, TEE_Param *params, uint32_t param_num);
typedef struct {
    hwsdp_msghandler msg_handler; /* hwsdp message handler */
    int32_t op_code; /* tee operate code */
} hwsdp_msghandler_map;

/*
 * This function securely frees allocated memory.
 * Contents are forced to be zero before allocated memory is freed.
 * @param [inout] buf  pointer that points to memory to be freed
 * @param [in] bufSize Length of memory to be freed.
 */
void secure_free(void *buf, uint32_t buf_size);

void hwsdp_destroy_all_modules(void);
uint32_t hwsdp_copy_data(hwsdp_data_info *src, uint8_t *dst_buf, uint32_t bufsz);
int32_t hwsdp_store_data(hwsdp_data_info *dst, const uint8_t *src, uint32_t src_len);
void hwsdp_release_data_buffer(hwsdp_data_info *data_info);
int32_t get_first_true_bit_idx(uint32_t num);
TEE_Result hwsdp_proc_message(uint32_t tee_cmd, uint32_t param_types, TEE_Param *params);

/* return code */
enum {
    HWSDP_TEE_FAILED = -1, /* normal error */
    HWSDP_TEE_SUCCESS = 0, /* success */
    HWSDP_TEE_OUT_OF_MEMORY , /* Out of memory */
    HWSDP_TEE_NULL_PTR , /* A pointer (that should not be null) is null */
    HWSDP_TEE_PAYLOAD_FORMAT_ERROR, /* Messages between kernel and TA are in wrong format */
    HWSDP_TEE_BAD_PARAMETER, /* bad params */
    HWSDP_TEE_MEMCPY_FAIL, /* failture in memcpy */
    HWSDP_TEE_ISEC_KEY_UNINITIALIZED, /* isecurity key is uninitialized */
    HWSDP_TEE_MEMORY_ALLOC_ERR, /* alloc memory failed */
    HWSDP_TEE_USER_ID_ERR, /* user id is uncurrect */
    HWSDP_TEE_KEY_NUMBER_ERR, /* key number is uncurrect */
    HWSDP_TEE_KEY_INFORMATION_ERR, /* key information is error */
    HWSDP_TEE_USER_NUMBER_ERR, /* user number is error */
    HWSDP_TEE_KEY_LENGTH_ERR /* the length of key is uncurrect */
};

#endif

