/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: get cert for kunpeng platform
 * Create: 2021-04
 */

#include "getcert.h"
#include <string.h>
#include <tee_log.h>
#include "boot_sharedmem.h"

int32_t get_certkey_info(uint8_t *buf, size_t len)
{
    int32_t ret;
    if (buf == NULL) {
        tloge("get info param error!\n");
        return -1;
    }
    if (len < TEEOS_SHAREDMEM_MODULE_SIZE_128K) {
        tloge("len is not stuff!\n");
        return -1;
    }

    ret = get_tlv_shared_mem_drv(SHARED_MEM_CERTKEY, strlen(SHARED_MEM_CERTKEY), buf, (uint32_t *)&len, false);
    if (ret != 0) {
        tloge("error get cert key info from sharedmem!\n");
        return ret;
    }
    return ret;
}
