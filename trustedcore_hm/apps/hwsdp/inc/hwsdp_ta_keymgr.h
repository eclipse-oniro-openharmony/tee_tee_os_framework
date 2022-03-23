/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file contains the key manager required declaration for TEE
 * Author: Huzhonghua h00440650
 * Create: 2020-10-19
 */

#ifndef HWSDP_TA_KEYMGR_H
#define HWSDP_TA_KEYMGR_H

#include "hwsdp_ta_utils.h"

#define ISEC_KEY_MAX_NUM 2

#define ISEC_KEY_TYPE_ECE 0x00000001u
#define ISEC_KEY_TYPE_SECE 0x00000002u

typedef struct {
    hwsdp_data_info *key[ISEC_KEY_MAX_NUM]; /* cache key data */
    int32_t user_id; /* user Id */
    uint32_t num; /* the number of cached keys */
} isec_key_mgr_blk;

enum {
    HWSDP_OPS_ADD_ISEC_KEY = 0, /* add a new key to HWDPS TEE */
    HWSDP_OPS_DEL_ISEC_KEY, /* delete a key from HWDPS TEE */
    HWSDP_OPS_GET_ISEC_KEY, /* get a added key from HWDPS TEE */
    HWSDP_OPS_MAX_CODE /* new commond must be added before this code */
};

hwsdp_msghandler get_isec_key_handler_by_opcode(int32_t op_code);
void destroy_isec_key_all_mgr_blk(void);

#endif
