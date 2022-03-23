/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc deriverkey for dx
 * Author: zhanglinhao
 * Create: 2020-12-23
 */

#ifndef _CC_DERIVEKEY_H
#define _CC_DERIVEKEY_H

CCUtilError_t UtilCmacDeriveKey(UtilKeyType_t keyType,
                                CCAesUserKeyData_t *pUserKey, uint8_t *pDataIn,
                                size_t dataInSize,
                                CCUtilAesCmacResult_t pCmacResult);
#endif
