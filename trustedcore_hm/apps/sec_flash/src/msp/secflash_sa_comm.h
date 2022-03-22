/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash sa communication.
 * Author: aaron.shen
 * Create: 2020-01-05
 */

#ifndef __SECFLASH_SA_COMM_H__
#define __SECFLASH_SA_COMM_H__

#include <stdint.h>
#include "tee_trusted_storage_api.h"

#define SECFLASH_DEBUG_ON  0

/*
 * 'A4' -- TEE
 * 'AE' --- MSP
 * '07' -- SECFLASH Moudle
 */
#define SECFLASH_TEE_FAILURE        0xA4070000
#define SECFLASH_MSP_FAILURE        0xAE070000

/* The information of a TA request. */
struct object_info {
    /* The same TA use obj_id to distinguish different object */
    uint8_t obj_id;
    /* A object with the same TA and the same obj_id can apply different memory type */
    uint8_t mem_type;
    /* the uuid pointer to the obj */
    TEE_UUID *uuid;
};

TEE_Result secflash_sa_alloc(struct object_info obj_info, uint32_t size);

TEE_Result secflash_sa_free(struct object_info obj_info);

TEE_Result secflash_sa_select(struct object_info obj_info, uint32_t *size, uint32_t len);

TEE_Result secflash_sa_set_offset(struct object_info obj_info, uint32_t *pos, int32_t offset, TEE_Whence whence);

TEE_Result secflash_sa_read(struct object_info obj_info, uint32_t pos, uint32_t size, uint8_t *buffer,
    uint32_t *count);

TEE_Result secflash_sa_write(struct object_info obj_info, uint32_t pos, uint32_t size, uint8_t *buffer);

TEE_Result secflash_sa_get_info(struct object_info obj_info, uint32_t cur_pos, uint32_t *pos, uint32_t *len);
#endif /* __SECFLASH_SA_COMM_H__ */