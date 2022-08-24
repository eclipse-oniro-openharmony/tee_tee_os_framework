/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: for check compatibility between tzdriver and tee
 * Author: lipeng
 * Create: 2021-7-12
 */

#include "tee_compat_check.h"
#include "tee_log.h"

void generate_teeos_compat_level(uint32_t *buffer, uint32_t size)
{
    if (buffer == NULL || size != COMPAT_LEVEL_BUF_LEN) {
        tloge("get compat level failed, param invalid\n");
        return;
    }

    buffer[0] = VER_CHECK_MAGIC_NUM;
    buffer[1] = TEEOS_COMPAT_LEVEL_MAJOR;
    buffer[2] = TEEOS_COMPAT_LEVEL_MINOR;
    return;
}
