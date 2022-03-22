/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: soft trng driver syscall
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */

#include "trng_api.h"
#include <errno.h>
#include <tee_bit_ops.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <param_check.h>
#include <drv_module.h>
#include <crypto_driver_adaptor.h>
#include <hmdrv_stub.h>
#include "drv_param_type.h"

#define LCG96_RAND_NUM    63
#define U32_VAL_MAX    0xffffffffull
#define U32_BITS    32
#define ARG0_INDEX           0
#define ARG1_INDEX           1
#define ARG2_INDEX           2

uint32_t g_seed = 0xa897213f;

enum {
    LCG96_U32_LOW = 0,
    LCG96_U32_MID = 1,
    LCG96_U32_HIG = 2,
    LCG96_U32_NUM = 3
};

/*
 * LCG(Linear Congruential Generator) is an algorithm that yields a sequence
 * of pseudo-randomized numbers calculated with a discontinuous piecewise
 * linear equation.
 * The generator is defined by recurrence relation:
 * X(i+1) = (a * X(i) + c) (mod m), i >= 0 && i < n
 * The "X(0...n-1)" is just the "g_lcg96_rand[]" array
 */
static unsigned long long g_lcg96_rand[LCG96_RAND_NUM];

/*
 * The "a" in the above formula is the g_multiplier, and its value is 5^41
 */
static const unsigned int g_multiplier[LCG96_U32_NUM] = {
    0x5aa1cae5,
    0xd0cf37be,
    0x92efd1b8
};

/*
 * Calculate: x1 = (g_multiplier[] * x0 + 1) (mod 2^96)
 */
static void lcg96_calc(const unsigned int *x0, unsigned int *x1)
{
    int i, j, k, h;
    unsigned int t[LCG96_U32_NUM];
    unsigned long long tmp, carry;

    for (i = 0; i < LCG96_U32_NUM; i++) {
        x1[i] = 0;
        t[i] = 0;
    }
    x1[0] = 1;

    for (i = 0; i < LCG96_U32_NUM; i++) {
        for (j = 0; j < LCG96_U32_NUM && (i + j) < LCG96_U32_NUM; j++) {
            tmp = (unsigned long long)g_multiplier[i] *
                  (unsigned long long)x0[j];
            t[1] = (unsigned int)(tmp >> U32_BITS);
            t[0] = (unsigned int)tmp;
            carry = 0ull;
            for (k = i + j; k < LCG96_U32_NUM; k++) {
                h = k - (i + j);
                tmp = (unsigned long long)x1[k] + t[h] + carry;
                carry = (tmp > U32_VAL_MAX) ? 1ull : 0ull;
                x1[k] = (unsigned int)tmp;
            }
        }
    }
}

static void random_seed(unsigned int seed)
{
#define LCG96_XI_NUM    2
    int i, j;
    unsigned int x_i[LCG96_XI_NUM][LCG96_U32_NUM];

    for (i = 0; i < LCG96_XI_NUM; i++)
        for (j = LCG96_U32_LOW; j < LCG96_U32_NUM; j++)
            x_i[i][j] = 0;

    x_i[0][LCG96_U32_LOW] = seed;
    j = 0;
    for (i = 0; i < LCG96_RAND_NUM; i++) {
        lcg96_calc(x_i[j], x_i[1 - j]);
        j = 1 - j;
        /* Take bits 95...32 of "Xi[]" as g_lcg96_rand numbers */
        g_lcg96_rand[i] =
            (unsigned long long)x_i[j][LCG96_U32_HIG] |
            ((unsigned long long)x_i[j][LCG96_U32_MID] << U32_BITS);
    }
    /* make sure g_lcg96_rand contains at least one odd number */
    g_lcg96_rand[0] |= 1ull;
#undef LCG96_XI_NUM
}

static void next_seed(void)
{
    g_seed = (uint32_t)(g_seed * 0x57e32a47 + 0x207c87a3);
}

static uint32_t random_arch_get(void)
{
    next_seed();
#define LCG96_OFFSET    5
    static int rand_idx = 1;
    int i = rand_idx;
    int j = (i + LCG96_OFFSET) % LCG96_RAND_NUM;

    random_seed(g_seed);

    g_lcg96_rand[j] += g_lcg96_rand[i];
    rand_idx = (rand_idx + 1) % LCG96_RAND_NUM;

    return (uint32_t)g_lcg96_rand[j];
#undef LCG96_OFFSET
}

int32_t trng_get_random(uint8_t *trng_addr, uint32_t length)
{
    uint32_t i;
    uint32_t value;
    uint32_t *tmp_addr = NULL;
    uint32_t left;
    errno_t ret;

    if (trng_addr == NULL) {
        tloge("bad param!\n");
        return -1;
    }

    left = length % WORD_SIZE;
    tmp_addr = (uint32_t *)trng_addr;

    for (i = 0; i < length / WORD_SIZE; i++) {
        tmp_addr[i] = random_arch_get();
        if (tmp_addr[i] == 0) {
            tloge("get rng value error!\n");
            return -1;
        }
    }

    if (left == 0)
        return 0;

    value = random_arch_get();
    ret = memcpy_s(trng_addr + i * WORD_SIZE, length - i * WORD_SIZE, (char *)(&value), left);
    if (ret) {
        tloge("copy random error!\n");
        return -1;
    }

    return 0;
}

int trng_driver_syscall(int swi_id, struct drv_param *params, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr;

    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_TRNG_GENERATE_RANDOM, ull_permissions, CC_RNG_GROUP_PERMISSION)
            tmp_addr = GET_64BIT_ADDR(args[ARG1_INDEX], args[ARG0_INDEX]);
            ACCESS_CHECK_A64(tmp_addr, args[ARG2_INDEX]);
            ACCESS_WRITE_RIGHT_CHECK(tmp_addr, args[ARG2_INDEX]);
            ret = trng_get_random((uint8_t *)(uintptr_t)tmp_addr, args[ARG2_INDEX]);
            args[ARG0_INDEX] = (uint32_t)ret;
        SYSCALL_END;

        default:
            return -1;
    }

    return 0;
}

DECLARE_TC_DRV(
    trng_syscall_init,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    trng_driver_syscall,
    NULL,
    NULL
);
