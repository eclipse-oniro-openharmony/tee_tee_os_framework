/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, DX function not export by libtee_shared.so
 * Create: 2019-11-25
 */
#ifndef DX_CCMGR_OPS_H
#define DX_CCMGR_OPS_H

#ifdef DX_ENABLE
#include "dx_cclib.h"
#include "crys_hash.h"
#include "crys_hmac.h"
#include "crys_des.h"
#include "crys_aes.h"
#include "crys_aesccm.h"
#include "crys_kdf.h"
#include "dx_util.h"
#include "crys_rnd.h"
#include "crys_rsa_build.h"
#include "crys_rsa_schemes.h"
#include "crys_rsa_prim.h"
#include "crys_dh.h"
#include "crys_ecpki_types.h"
#include "dx_cc_defs.h"
#include "dx_util_oem_asset.h"

CRYSError_t __CC_CRYS_AES_SetIv(CRYS_AESUserContext_t *ContextID_ptr, DxUint8_t *iv_ptr, DxUint32_t iv_size);
CRYSError_t __CC_CRYS_AESCCM_Init(CRYS_AESCCM_UserContext_t *ContextID_ptr, CRYS_AES_EncryptMode_t EncrDecrMode,
                                  CRYS_AESCCM_Key_t CCM_Key, CRYS_AESCCM_KeySize_t KeySizeId,
                                  DxUint32_t AdataSize, DxUint32_t TextSize, DxUint8_t *N_ptr, DxUint8_t SizeOfN,
                                  DxUint8_t SizeOfT);
CRYSError_t __CC_CRYS_AESCCM_BlockAdata(CRYS_AESCCM_UserContext_t *ContextID_ptr, DxUint8_t *DataIn_ptr,
                                        DxUint32_t DataInSize);
CRYSError_t __CC_CRYS_AESCCM_BlockTextData(CRYS_AESCCM_UserContext_t *ContextID_ptr, DxUint8_t *DataIn_ptr,
                                           DxUint32_t DataInSize, DxUint8_t *DataOut_ptr);
CRYSError_t __CC_CRYS_AESCCM_Finish(CRYS_AESCCM_UserContext_t *ContextID_ptr, DxUint8_t *DataIn_ptr,
                                    DxUint32_t DataInSize, DxUint8_t *DataOut_ptr, CRYS_AESCCM_Mac_Res_t MacRes,
                                    DxUint8_t *SizeOfT);
CRYSError_t __CC_CRYS_DH_GetSecretKey(DxUint8_t *ClientPrvKey_ptr, DxUint16_t ClientPrvKeySize,
                                      DxUint8_t *ServerPubKey_ptr, DxUint16_t ServerPubKeySize,
                                      DxUint8_t *Prime_ptr, DxUint16_t PrimeSize,
                                      CRYS_DHUserPubKey_t *tmpPubKey_ptr, CRYS_DHPrimeData_t *tmpPrimeData_ptr,
                                      DxUint8_t *SecretKey_ptr, DxUint16_t *SecretKeySize_ptr);
CRYSError_t __CC_CRYS_RSA_Get_PrivKeyCRT(CRYS_RSAUserPrivKey_t *UserPrivKey_ptr, DxUint8_t *P_ptr,
                                         DxUint16_t *PSize_ptr, DxUint8_t *Q_ptr, DxUint16_t *QSize_ptr,
                                         DxUint8_t *dP_ptr, DxUint16_t *dPSize_ptr, DxUint8_t *dQ_ptr,
                                         DxUint16_t *dQSize_ptr, DxUint8_t *qInv_ptr, DxUint16_t *qInvSize_ptr);
DxUTILError_t __DX_UTIL_OemAssetUnpack(DX_UTIL_OemKey_t pOemKey, DxUint32_t assetId, DxUint8_t *pAssetPackage,
                                       DxUint32_t assetPackageLen, DxUint8_t *pAssetData,
                                       DxUint32_t *pAssetDataLen, DxUint32_t *pUserData);
// ecc
_Bool __CC_EPS_SupportCdrmEnhance();
CRYSError_t __CC_EPS_CTRL(uint32_t type, uint32_t profile);
int32_t __cc_eps_sm2_sign(void *private_key, uint8_t *input, uint32_t input_len, void *signature);
int32_t __cc_eps_sm2_verify(void *public_key, uint8_t *input, uint32_t input_len, void *signature);
int32_t __cc_eps_sm2_encrypt(void *private_key, uint8_t *input, uint32_t input_len, void *cipher, uint32_t clen);
int32_t __cc_eps_sm2_decrypt(void *public_key, uint8_t *output, uint32_t *output_len, void *cipher,
                             uint32_t clen);
int32_t __cc_eps_sm4_symmetric_encrypt(uint32_t algo, void *params);
int32_t __cc_eps_sm4_symmetric_decrypt(uint32_t algo, void *params);
int32_t __cc_eps_sm4_config(void *context, void *param);
int32_t __cc_eps_sm4_cenc_decrypt(void *context, void *param);
#endif

#endif /* DX_CCMGR_OPS_H */
