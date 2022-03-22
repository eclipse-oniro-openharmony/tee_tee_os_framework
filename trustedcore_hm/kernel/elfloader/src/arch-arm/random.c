/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: timer read function
 * Create: 2020-12
 */
#include <log.h>
#include <data.h>
#include <assert.h>
#include <string.h>
#include <arch-arm/timer.h>
#include <arch-arm/data.h>
#include <arch-arm/random.h>

#define LCG96_RAND_NUM    63
#define U32_VAL_MAX    0xffffffffull
#define U32_BITS    32

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

    for (i = 0; i < LCG96_XI_NUM; i++) {
        for (j = LCG96_U32_LOW; j < LCG96_U32_NUM; j++) {
            x_i[i][j] = 0;
        }
    }
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

static uint64_t random_arch_get(uint32_t seed)
{
#define LCG96_OFFSET    5
    static int rand_idx = 1;
    int i = rand_idx;
    int j = (i + LCG96_OFFSET) % LCG96_RAND_NUM;

    random_seed(seed);

    g_lcg96_rand[j] += g_lcg96_rand[i];
    rand_idx = (rand_idx + 1) % LCG96_RAND_NUM;

    return (uint64_t)g_lcg96_rand[j];
#undef LCG96_OFFSET
}

#if defined(CONFIG_ASCEND_PLATFORM)
static uint32_t get_seed()
{
    uint32_t tmp_rand;
    uint32_t time = 0;

    /* plat_io_regions index 2 is trng for ascend */
    paddr_t trng_addr = g_plat_cfg.plat_io_regions[1].start;

    do {
        tmp_rand = rand_read32(trng_addr + 0xf0);
        if (tmp_rand != 0)
            break;

        time++;
    } while (time < RD_RETRY_LIMIT);

    return tmp_rand;
}

#elif defined(CONFIG_EL3_RANDOM)
static uintptr_t get_rand_addr_el3()
{
    /* using last TEEOS_RANDOM_SEED_SIZE bytes of SHAREDMEM_COLORLOCK buffer in the sharemem */
    uintptr_t sharedmem_base = (uintptr_t)elfloader_paddr_to_vaddr(g_plat_cfg.phys_region_start +
                                                                   g_plat_cfg.shmem_offset);
    uintptr_t random_seed_addr = sharedmem_base + TEEOS_SHAREDMEM_OFFSET_COLORLOCK
              + TEEOS_SHAREDMEM_MODULE_SIZE_512 - TEEOS_RANDOM_SEED_SIZE;

    return random_seed_addr;
}

static uint32_t get_seed()
{
    uintptr_t random_seed_addr = get_rand_addr_el3();
    uint32_t random_seed = *(uint32_t *)random_seed_addr;
    if (random_seed == 0)
        klog(DEBUG_WARNING, "el3 seed is zero\n");

    return random_seed;
}

#else
static uint32_t get_seed()
{
    return (uint32_t)arch_timer_read();
}

#endif

uint64_t rand_get(uint32_t seed)
{
    const uint32_t seed_tmp = get_seed();
    if (seed_tmp != 0)
        seed = seed_tmp;

    return random_arch_get(seed);
}

void rand_clear()
{
    int ret;

#if defined(CONFIG_EL3_RANDOM)
    /* clear rand addr from el3 */
    uintptr_t rand_addr_el3 = get_rand_addr_el3();
    ret = memset((void *)rand_addr_el3, 0, TEEOS_RANDOM_SEED_SIZE);
    if (ret != 0)
        klog(DEBUG_ERROR, "rand_clear_from_el3 failed\n");
#endif

    /* clear local rand */
    ret = memset(g_lcg96_rand, 0, sizeof(g_lcg96_rand));
    if (ret != 0)
        klog(DEBUG_ERROR, "rand clear g_lcg96_rand failed\n");
}
