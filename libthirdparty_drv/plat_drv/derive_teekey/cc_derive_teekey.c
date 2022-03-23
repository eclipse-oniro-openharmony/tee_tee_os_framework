/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: plat capability, key derive
 * Create: 2021-05
 */
#include <securec.h>
#include "derive_teekey.h"
#include <plat_cap.h>
#include <plat_rotpk.h>
#include <cc_power.h>
#include <securec.h>
#include <drv_legacy_def.h>

#define ROTPK_HASH_BYTE_SIZE   32
#define ROTPK_HASH_WORD_SIZE   (ROTPK_HASH_BYTE_SIZE / 4)

#ifndef MAX
#define MAX(a, b)    ((a) > (b) ? (a) : (b))
#endif

#if (PLAT_TEEKEY_SIZE & (PLAT_TEEKEY_SIZE - 1))
#error "PLAT_TEEKEY_SIZE is not tht power of 2"
#endif

#define BUF_ALIGN_SIZE   MAX(PLAT_TEEKEY_SIZE, OS_CACHE_LINE_SIZE)
#define SEED_ALIGN_SIZE  MAX(ROTPK_HASH_BYTE_SIZE, OS_CACHE_LINE_SIZE)

static uint8_t g_buf[PLAT_TEEKEY_SIZE] __attribute__((aligned(BUF_ALIGN_SIZE))) ;
static uint32_t g_seed[ROTPK_HASH_WORD_SIZE] __attribute__((aligned(SEED_ALIGN_SIZE))) = {ROTPK_HASH};

static uint32_t do_derive_teekey(uint8_t *key, uint32_t size)
{
	uint32_t ret;

	if (!key) {
		tloge("error, key is NULL\n");
		return 1;
	}

	if (size != PLAT_TEEKEY_SIZE) {
		tloge("error, size 0x%x is illegal\n", size);
		return 1;
	}

	ret = seb_derive_provkey(g_buf, g_seed);
	if (ret) {
		tloge("error 0x%x, derive teekey\n", ret);
		ret = 1;
		goto exit;
	}

	ret = memcpy_s(key, size, g_buf, sizeof(g_buf));
	if (ret != EOK) {
		tloge("error 0x%x, cp g_buf to k\n", ret);
		ret = 1;
		goto exit;
	}
exit:
	(void)memset_s(g_buf, sizeof(g_buf), 0, sizeof(g_buf));

	return ret;
}

uint32_t plat_derive_teekey(uint8_t *key, uint32_t size)
{
	uint32_t ret, res;

	res = secs_power_on();
	if (res != 0) {
		tloge("error 0x%x, secs power on\n", res);
		return 1;
	}

	ret = do_derive_teekey(key, size);

	res = secs_power_down();
	if (res != 0) {
		tloge("error 0x%x, secs power down\n", res);
		return 1;
	}

	return ret;
}
