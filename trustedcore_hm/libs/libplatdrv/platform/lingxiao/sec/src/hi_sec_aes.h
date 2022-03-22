/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: ASE 算法相关定义
 * Author: o00302765
 * Create: 2019-10-22
 */

#ifndef __HI_SEC_AES_H__
#define __HI_SEC_AES_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#define HI_SEC_AES_BLOCK_SIZE 16
#define HI_SEC_AES_MIN_KEY_SIZE	16
#define HI_SEC_AES_MED_KEY_SIZE	24
#define HI_SEC_AES_MAX_KEY_SIZE	32
#define HI_SEC_AES_XCM_MAX_NONCE_LEN 13
#define HI_SEC_AES_XCM_MIN_NONCE_LEN 8
#define HI_SEC_AES_GCM_MAX_IV_LEN 12
#define HI_SEC_IV_SIZE 16  /* AES: 128 Bits; DES/3DES: 64 Bits, AES-XTS模式用作seqnum */

hi_int32 hi_sec_aes_bd_fragment(struct hi_sec_bd_desc_s *origin);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_SEC_AES_H__ */
