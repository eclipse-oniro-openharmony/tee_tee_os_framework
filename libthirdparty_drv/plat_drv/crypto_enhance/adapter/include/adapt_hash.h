/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: declare of hash api(same as dx)
 * Author     : l00370476
 * Create     : 2018/12/28
 */

#ifndef __ADAPT_HASH_H__
#define __ADAPT_HASH_H__

#include <cc_hash.h>
#include <cc_hash_error.h>

uint32_t GetHashAlgorithm(CCHashOperationMode_t OperationMode);

CEXPORT_C CCError_t EPS_HashInit(CCHashUserContext_t *ContextID_ptr, CCHashOperationMode_t   OperationMode);

CEXPORT_C CCError_t EPS_HashUpdate(CCHashUserContext_t *ContextID_ptr, uint8_t *DataIn_ptr, size_t DataInSize);

CEXPORT_C CCError_t EPS_HashFinish(CCHashUserContext_t *ContextID_ptr, CCHashResultBuf_t HashResultBuff);

CEXPORT_C CCError_t EPS_Hash(CCHashOperationMode_t OperationMode, uint8_t *DataIn_ptr, size_t DataSize,
			     CCHashResultBuf_t HashResultBuff);

CEXPORT_C CCError_t EPS_HashFree(CCHashUserContext_t *ContextID_ptr);

#endif

