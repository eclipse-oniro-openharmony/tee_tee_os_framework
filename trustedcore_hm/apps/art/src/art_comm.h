/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: antiroll-back token sa communication header file.
 * Author: aaron.shen
 * Create: 2020-03-21
 */

#ifndef __ART_COMM_H__
#define __ART_COMM_H__

#include <stdint.h>
#include "tee_trusted_storage_api.h"

#define ART_DEBUG_ON  0

#define ART_SUCCESS            TEE_SUCCESS

/*
 * 'A4' -- TEE  'AE' --- MSP
 * '08' -- ART Moudle
 */
#define ART_TEE_FAILURE        0xA4080000
#define ART_MSP_FAILURE        0xAE080000

TEE_Result art_sa_alloc(TEE_UUID *uuid, uint32_t *counter_num);

TEE_Result art_sa_read_counter(TEE_UUID *uuid, uint32_t counter_id, uint32_t *counter);

TEE_Result art_sa_increase_counter(TEE_UUID *uuid, uint32_t counter_id, uint32_t *counter);
#endif /* __ART_COMM_H__ */
