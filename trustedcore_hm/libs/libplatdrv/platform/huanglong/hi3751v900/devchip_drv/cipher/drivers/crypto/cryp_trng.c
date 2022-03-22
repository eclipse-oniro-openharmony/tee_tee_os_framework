/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: crypto tmg
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "drv_osal_lib.h"
#include "drv_trng.h"
#include "cryp_trng.h"

/********************** Internal Structure Definition ************************/
/** \addtogroup      trng */
/** @{ */ /** <!-- [trng] */

/* the max continuous bits of randnum is allowed */
#define CONTINUOUS_BITS_ALLOWD 0x08

/* times try to read rang */
#define RANG_READ_TRY_TIME 0x40

/** @} */ /** <!-- ==== Structure Definition end ==== */

/******************************* API Code *****************************/
/** \addtogroup      trng drivers */
/** @{ */ /** <!-- [trng] */

#ifdef CHIP_TRNG_SUPPORT

hi_s32 cryp_trng_init(void)
{
    hi_s32 ret;

    hi_log_func_enter();

    ret = drv_trng_init();
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(drv_trng_init, ret);
        return ret;
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 cryp_trng_deinit(void)
{
    hi_s32 ret;

    hi_log_func_enter();

    ret = drv_trng_deinit();
    if (ret != HI_SUCCESS) {
        hi_log_print_func_err(drv_trng_deinit, ret);
        return ret;
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

static hi_s32 cryp_trng_check(hi_u32 randnum)
{
    /* continuous 32 bits0 or bit1 is prohibited */
    if ((randnum == 0xffffffff) || (randnum == 0x00000000)) {
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 cryp_trng_get_random(hi_u32 *randnum, hi_u32 timeout)
{
    hi_u32 i = 0;
    hi_s32 ret;

    hi_log_func_enter();

    for (i = 0; i < RANG_READ_TRY_TIME; i++) {
        ret = drv_trng_randnum(randnum, timeout);
        if (ret != HI_SUCCESS) {
            return ret;
        }

        ret = cryp_trng_check(*randnum);
        if (ret == HI_SUCCESS) {
            break;
        }
    }

    if (i >= RANG_READ_TRY_TIME) {
        hi_log_error("error, trng randnum check failed\n");
        return HI_ERR_CIPHER_NO_AVAILABLE_RNG;
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

hi_s32 cryp_trng_get_random_bytes(hi_u8 *randbyte, hi_u32 size, hi_u32 timeout)
{
    hi_s32 ret;
    hi_u32 i;
    hi_u32 cnt;
    hi_u32 randnum = 0;

    hi_log_func_enter();

    cnt = size / WORD_WIDTH;
    for (i = 0; i < cnt; i++) {
        ret = cryp_trng_get_random(&randnum, timeout);
        if (ret != HI_SUCCESS) {
            return ret;
        }
        ret = memcpy_s(randbyte, WORD_WIDTH, &randnum, WORD_WIDTH);
        if (ret != HI_SUCCESS) {
            hi_log_print_func_err(memset_s, ret);
            return ret;
        }
        randbyte += WORD_WIDTH;
    }

    /* less then 4 byte */
    for (i = cnt * WORD_WIDTH; i < size; i++) {
        ret = cryp_trng_get_random(&randnum, timeout);
        if (ret != HI_SUCCESS) {
            return ret;
        }
        *randbyte++ = randnum & 0xFF;
    }

    hi_log_func_exit();
    return HI_SUCCESS;
}

#endif

/** @} */ /** <!-- ==== API Code end ==== */
