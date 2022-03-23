/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the definition required for free
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */

#include "bdkernel_utils.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"

/* invoke the TEE interface to free the buf */
void SecureFree(void *buf, uint32_t bufSize)
{
    if (memset_s(buf, bufSize, 0, bufSize) != EOK) {
        SLogError("memset_s failed in secureFree");
    }
    TEE_Free(buf);
}
