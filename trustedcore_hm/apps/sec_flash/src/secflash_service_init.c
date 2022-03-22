/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Secure flash service initalization management.
 * Author: chengruhong
 * Create: 2020-01-20
 * Notes:
 * History: 2020-01-20 chengruhong create
 */
#include "secflash_service_init.h"
#include "secflash_mm.h"
#include "secflash_scp03_comm.h"
#include "tee_log.h"

#define SECFLASH_SERVICE_INITED 0x6675636B
#define SECFLASH_SERVICE_NOT_INITED 0x12345678

static uint32_t g_secflash_service_init_flag = SECFLASH_SERVICE_NOT_INITED;

/*
 * @brief     : Initialize the secure flash service.
 * @param[in] : void
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status.
 */
void secflash_service_init(void)
{
    uint32_t ret;
    if (g_secflash_service_init_flag == SECFLASH_SERVICE_INITED)
        return;

    ret = secflash_scp03_init();
    if (ret != TEE_SUCCESS)
        tloge("%s, rv=0x%x, failed.\n", __func__, ret);

    secflash_mm_init(ret);

    g_secflash_service_init_flag = SECFLASH_SERVICE_INITED;
}

/*
 * @brief     : Reset the initialization flag.
 * @param[in] : void
 * @param[out]: void
 * @return    : void
 */
void secflash_service_reset_init_flag(void)
{
    g_secflash_service_init_flag = SECFLASH_SERVICE_NOT_INITED;
}
