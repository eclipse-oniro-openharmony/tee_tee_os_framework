/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: adapter rng api
 * Author: s00294296
 * Create: 2020-03-31
 */
#include <adapter_rng.h>
#include <hisee_rng.h>
#include <pal_log.h>

#define BSP_THIS_MODULE BSP_MODULE_RNG

void adapter_generate_random(void *buffer, size_t size)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = hisee_rng_gen_trnd((u8 *)buffer, size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		PAL_ERROR("gen trng error!\n");
}

