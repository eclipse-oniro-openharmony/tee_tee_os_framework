/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description  : adapt dx hash interface
 * Author       : l00370476, liuchong13@huawei.com
 * Create       : 2018/12/25
 */
#include <adapt_hash.h>
#include <pal_libc.h>
#include <pal_log.h>
#include <hieps_agent.h>
#include <api_hash.h>
#include "adapt_common.h"

u32 GetHashAlgorithm(CCHashOperationMode_t OperationMode)
{
	switch (OperationMode) {
	case CC_HASH_SHA1_mode:
		return SYMM_ALGORITHM_SHA1;
	case CC_HASH_SHA256_mode:
		return SYMM_ALGORITHM_SHA256;
	case CC_HASH_MD5_mode:
		return SYMM_ALGORITHM_MD5;
	case CC_HASH_SM3_mode:
		return SYMM_ALGORITHM_SM3;
	default:
		return SYMM_ALGORITHM_UNKNOWN;
	}
}

CEXPORT_C CCError_t EPS_HashInit(
	CCHashUserContext_t   *ContextID_ptr,
	CCHashOperationMode_t  OperationMode)
{
	api_hash_ctx_s *pctx = (api_hash_ctx_s *)ContextID_ptr;
	u32 algorithm;
	err_bsp_t ret;

	if (!ContextID_ptr)
		return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;

	if (OperationMode >= CC_HASH_NumOfModes)
		return CC_HASH_ILLEGAL_OPERATION_MODE_ERROR;

	(void)memset_s(ContextID_ptr, sizeof(*ContextID_ptr), 0, sizeof(*ContextID_ptr));

	algorithm = GetHashAlgorithm(OperationMode);

	ret = api_hash_init(pctx, algorithm);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

CEXPORT_C CCError_t EPS_HashUpdate(
	CCHashUserContext_t  *ContextID_ptr,
	u8                   *DataIn_ptr,
	size_t                DataInSize)
{
	err_bsp_t ret;
	api_hash_ctx_s *pctx = (api_hash_ctx_s *)ContextID_ptr;
	pal_master_addr_t pdin = DataIn_ptr;
	u32 dinlen = DataInSize;

	/* check param */
	if (!ContextID_ptr)
		return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;

	if (DataInSize == 0)
		return CC_OK;

	if (!DataIn_ptr)
		return CC_HASH_DATA_IN_POINTER_INVALID_ERROR;

	/* call agent */
	ret = api_hash_update(pctx, pdin, dinlen);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

CEXPORT_C CCError_t EPS_HashFinish(CCHashUserContext_t *ContextID_ptr,
				   CCHashResultBuf_t HashResultBuff)
{
	err_bsp_t ret;
	api_hash_ctx_s *pctx = (api_hash_ctx_s *)ContextID_ptr;
	pal_master_addr_t pdin = 0;
	u8 *pdout = (u8 *)HashResultBuff;
	u32 doutlen = CC_HASH_RESULT_SIZE_IN_WORDS * sizeof(u32);

	/* check param */
	if (!ContextID_ptr)
		return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;

	if (!HashResultBuff)
		return CC_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR;

	/* call agent */
	ret = api_hash_dofinal(pctx, pdin, 0, pdout, &doutlen);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

CEXPORT_C CCError_t  EPS_HashFree(CCHashUserContext_t *ContextID_ptr)
{
	if (!ContextID_ptr)
		return CC_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;

	(void)memset_s(ContextID_ptr, sizeof(*ContextID_ptr), 0, sizeof(*ContextID_ptr));

	return CC_OK;
}

CEXPORT_C CCError_t EPS_Hash(CCHashOperationMode_t   OperationMode,
			     u8                     *DataIn_ptr,
			     size_t                  DataSize,
			     CCHashResultBuf_t       HashResultBuff)
{
	CCError_t error;
	CCError_t error_result;
	CCHashUserContext_t user_context;

	error = EPS_HashInit(&user_context, OperationMode);
	if (error != CC_OK)
		goto end;

	error = EPS_HashUpdate(&user_context, DataIn_ptr, DataSize);
	if (error != CC_OK)
		goto end;

	error = EPS_HashFinish(&user_context, HashResultBuff);
	if (error != CC_OK)
		goto end;

end:
	error_result = EPS_HashFree(&user_context);
	if (error != CC_OK)
		return error;
	return error_result;
}

