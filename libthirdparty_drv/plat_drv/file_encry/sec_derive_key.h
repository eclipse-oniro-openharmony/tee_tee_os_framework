/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Library for FBE2
 * Create: 2018-06-11
 */
#ifndef __SEC_DERIVE_KEY_H__
#define __SEC_DERIVE_KEY_H__
#include "cc_adapt.h"
#include "cc_lib.h"
#include "cc_util_defs.h"

CCUtilError_t DX_UTIL_CmacDeriveKey(UtilKeyType_t keyType,
				    uint8_t *pDataIn,
				    size_t dataInSize,
				    CCUtilAesCmacResult_t pCmacResult);

CCUtilError_t DX_UTIL_UserDeriveKey(UtilKeyType_t keyType,
				    CCAesUserKeyData_t *pUserKey,
				    uint8_t *pDataIn,
				    size_t dataInSize,
				    CCUtilAesCmacResult_t pCmacResult);
uint32_t secboot_get_fbe2_flag(uint8_t *fbe2_flag);
#endif
