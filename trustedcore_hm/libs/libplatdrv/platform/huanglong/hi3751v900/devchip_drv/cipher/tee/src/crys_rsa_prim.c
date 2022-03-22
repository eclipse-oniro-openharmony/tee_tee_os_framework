/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: rsa prim
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_type_dev.h"
#include "drv_osal_lib.h"
#include "crys_aes.h"
#include "dx_pal_types.h"
#include "crys_rsa_error.h"
#include "crys_rsa_types.h"
#include "crys_rsa_local.h"
#include "crys_rsa_schemes.h"

CEXPORT_C CRYSError_t CRYS_RSA_PRIM_Encrypt(CRYS_RSAUserPubKey_t *UserPubKey_ptr,
                                            CRYS_RSAPrimeData_t *PrimeData_ptr,
                                            DxUint8_t *Data_ptr,
                                            DxUint16_t DataSize,
                                            DxUint8_t *Output_ptr)
{
    return _DX_RSA_SCHEMES_Encrypt(UserPubKey_ptr, PrimeData_ptr,
                                   CRYS_RSA_HASH_NO_HASH_mode, HI_NULL, 0, CRYS_PKCS1_NO_MGF,
                                   Data_ptr, DataSize, Output_ptr, CRYS_PKCS1_VER21);
}

CEXPORT_C CRYSError_t CRYS_RSA_PRIM_Decrypt(CRYS_RSAUserPrivKey_t *UserPrivKey_ptr,
                                            CRYS_RSAPrimeData_t *PrimeData_ptr,
                                            DxUint8_t *Data_ptr,
                                            DxUint16_t DataSize,
                                            DxUint8_t *Output_ptr)
{
    hi_u16 len = 0;

    return _DX_RSA_SCHEMES_Decrypt(UserPrivKey_ptr, PrimeData_ptr,
                                   CRYS_RSA_HASH_NO_HASH_mode, HI_NULL, 0, CRYS_PKCS1_NO_MGF,
                                   Data_ptr, DataSize, Output_ptr, &len, CRYS_PKCS1_VER21);
}

