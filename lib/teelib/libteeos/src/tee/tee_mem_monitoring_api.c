/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Implemetion of memory management not GP api
 * Author: luozhengyi l00575763
 * Create: 2022-04-25
 */

#include "tee_mem_mgmt_api.h"

#include <mem_ops.h>
#include "tee_log.h"
#include "hm_mman.h"

uint32_t get_heap_usage(bool show)
{
    uint32_t mem_usage = get_heap_used();

    if (show)
        tloge("heap usage = %u%%\n", mem_usage);

    return mem_usage;
}
