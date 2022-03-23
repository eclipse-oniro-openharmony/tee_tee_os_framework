/*
 *Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *Description: get chip unique id, called by TA
 *Create: 2021/02/07
 */

#include "secboot_cuid.h"
#include "secboot_drv_call.h"
#include "tee_log.h"

TEE_Result seb_get_cuid(uint8_t *cuid, uint32_t len)
{
	TEE_Result ret;

	if (!cuid || len < SECBOOT_CUID_BYTES) {
		tloge("%s,param error\n",__func__);
		return TEE_ERROR_GENERIC;
	}

	ret = __secboot_get_cuid(cuid, len);
	if (ret != TEE_SUCCESS) {
		tloge("error 0x%x,get chip unique ID\n",ret);
		return TEE_FAIL;
	}
	return TEE_SUCCESS;
}
