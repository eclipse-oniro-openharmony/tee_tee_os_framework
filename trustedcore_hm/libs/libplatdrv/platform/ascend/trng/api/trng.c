/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: the internal trng.c
* Author: huawei
* Create: 2019/12/30
*/
#include "tee_log.h"
#include "tee_defines.h"

#include <securec.h>

#include "trng.h"
#include "trng_api.h"
#include "trng_internal_api.h"
#include "register_ops.h"

uint32_t trng_get_data_use(uint8_t *trngstore_addr, uint32_t trng_len)
{
    uint32_t buffer[RANDATA_SIZE];
    uint32_t zero_cnt = 0;

    if ((trng_len != TRNG_NORMAL_LEN) || (trngstore_addr == NULL)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    do {
        buffer[STORE_OFF0] = read32(TRNG_RAN_DATA0_REG);
        buffer[STORE_OFF1] = read32(TRNG_RAN_DATA1_REG);
        buffer[STORE_OFF2] = read32(TRNG_RAN_DATA2_REG);
        buffer[STORE_OFF3] = read32(TRNG_RAN_DATA3_REG);
        zero_cnt++;
    } while ((TRNG_READ_IS_ZERO(buffer) != 0) && (zero_cnt < TRNG_READ_ZERO_TIMEOUT));

    if (zero_cnt == TRNG_READ_ZERO_TIMEOUT) {
        tloge("trng status is abnormal.\n");
        return TRNG_ERR_STATUS_TIMEOUT;
    }

    if (memcpy_s((void *)trngstore_addr, trng_len, (const void *)buffer, TRNG_NORMAL_LEN) != EOK) {
        tloge("trng memcopy is wrong\n");
        return TRNG_ERR_MEMCPY_FAILED;
    }

    return TRNG_SUCCESS;
}
