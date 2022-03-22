/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: dynion driver func
 * Author: Heyanhong heyanhong2@huawei.com
 * Create: 2020-09-07
 */
#include "dynion_config.h"
#include "tee_log.h"
#include "secmem_core_api.h"
#include "secmem.h"

int32_t set_dynmem_config(struct sglist *sglist, int32_t type)
{
    int32_t ret;
    uint64_t start_addr;
    uint32_t size;

    ret = get_dynmem_addr(sglist, type, &start_addr, &size);
    if (ret != 0)
        return ret;

    mem_cfg_para_s mem_config = {0};
    mem_config.in_type = MEM_INPUT_ADDR;
    mem_config.input.para_addr.phy_addr = start_addr;
    mem_config.input.para_addr.size = size;
    mem_config.mem_type = T_MPU_REQ_ORIGIN_TEE_ZONE_EID;

    if (((uint32_t)type & DDR_CFG_TYPE_BITS) == DDR_SET_SEC) {
        ret = secmem_sec_cfg(&mem_config, SECMEM_SVC_ID, SECURE_MEM_ENABLE);
    } else if (((uint32_t)type & DDR_CFG_TYPE_BITS) == DDR_UNSET_SEC) {
        ret = secmem_sec_cfg(&mem_config, SECMEM_SVC_ID, SECURE_MEM_DISABLE);
    } else {
        tloge("memtype:%d not support\n", type);
        return -1;
    }

    uart_printf_func("set dynmem config size=%u, type=%d, ret=%d\n", size, type, ret);

    return ret;
}
