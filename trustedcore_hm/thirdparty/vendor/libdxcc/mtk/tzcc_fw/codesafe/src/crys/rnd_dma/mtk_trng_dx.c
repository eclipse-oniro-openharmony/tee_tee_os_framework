/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mtk hardware random generator
 * Author: heyanhong heyanhong2@huawei.com
 * Create: 2020-10-09
 */
#include "mtk_trng_dx.h"
#include <stdint.h>
#include <stdio.h>
#include <tee_log.h>
#include "ipc_call.h"

void mtk_trng(uint32_t *rand)
{
    uint32_t value;

    if (rand == NULL)
        return;

    /* ungate */
    *((volatile uint32_t *)(TRNG_PDN_CLR)) = TRNG_PDN_VALUE;

    /* read random data once and drop it */
    value = *((volatile uint32_t *)(TRNG_DATA));

    /* enable von-neumann extractor */
    value = *((volatile uint32_t *)(TRNG_CONF));
    value |= TRNG_CONF_VON_EN;
    *((volatile uint32_t *)(TRNG_CONF)) = value;

    /* start */
    value = *((volatile uint32_t *)(TRNG_CTRL));
    value |= TRNG_CTRL_START;
    *((volatile uint32_t *)(TRNG_CTRL)) = value;

    /* get seeds from trng */
    while ((*((volatile uint32_t *)(TRNG_CTRL)) & TRNG_CTRL_RDY) == 0);
    *(rand) = *((volatile uint32_t *)(TRNG_DATA));

    /* stop */
    value = *((volatile uint32_t *)(TRNG_CTRL));
    value &= ~TRNG_CTRL_START;
    *((volatile uint32_t *)(TRNG_CTRL)) = value;

    /* gate */
    *((volatile uint32_t *)(TRNG_PDN_SET)) = TRNG_PDN_VALUE;
}

static int32_t get_trng_lock(void)
{
    kcall_tee_smc_atf_t param = {0};
    uint32_t lock_cmd = 0xb2000013;

    int32_t ret = switch_to_atf_ret(lock_cmd, &param);
    if (ret  != 0) {
        printf("get trng lock failed ret:0x%x\n", ret);
        return -1;
    }

    return 0;
}

static int32_t get_trng_unlock(void)
{
    kcall_tee_smc_atf_t param = {0};
    uint32_t unlock_cmd = 0xb2000014;

    int32_t ret = switch_to_atf_ret(unlock_cmd, &param);
    if (ret  != 0) {
        printf("get trng unlock failed ret:0x%x\n", ret);
        return -1;
    }

    return 0;
}

int32_t mtk_get_trng(uint8_t *buff, uint32_t length)
{
    uint32_t trng_val = 0;
    uint32_t i = 0;
    uint32_t remain = 0;
    uint32_t j = 0;

    if (buff == NULL || length == 0) {
        printf("buff or length invalid\n");
        return -1;
    }

    if (get_trng_lock() != 0)
        return -1;

    if (length < sizeof(uint32_t)) {
        remain = length;
        goto get_remain;
    }

    uint32_t count = length / sizeof(uint32_t);
    uint32_t *rbuff = (uint32_t *)buff;
    for (i = 0; i < count; i++) {
        mtk_trng(&trng_val);
        rbuff[i] = trng_val;
    }

    remain = length % sizeof(uint32_t);

get_remain:
    if (remain != 0) {
        mtk_trng(&trng_val);
        for (j = 0; j < remain; j++)
            buff[i * sizeof(uint32_t) + j] = (uint8_t)(trng_val >> (j * 8));
    }

    (void)get_trng_unlock();

    return 0;
}
