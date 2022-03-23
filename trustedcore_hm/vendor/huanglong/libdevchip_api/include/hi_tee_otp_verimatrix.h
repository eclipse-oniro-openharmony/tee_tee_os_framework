/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file is the header file of the otp driver.
 * Author: Hisilicon hisecurity group
 * Create: 2019-12-28
 */
#ifndef __HI_TEE_OTP_VERIMATRIX_H__
#define __HI_TEE_OTP_VERIMATRIX_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*************************** Structure Definition ****************************/
/** \addtogroup      OTP_VERIMATRIX */
/** @{ */  /** <!-- [OTP_VERIMATRIX] */

/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API declaration *****************************/
/** \addtogroup      OTP_VERIMATRIX */
/** @{ */  /** <!-- [OTP_VERIMATRIX] */

/**
\brief Set antirollback version
\brief CNcomment ���÷��ع��汾�š� CNend
\attention \n
N/A
\param[in] addr:    OTP address.                       CNcomment:OTP ��ַ�� CNend
\param[in] length:  The length of otp.                 CNcomment:���ع��汾��OTP���ȡ� CNend
\param[in] version:  The version of otp.               CNcomment:���õ�version�� CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_verimatrix_set_anti_rollback_version(hi_u32 addr, hi_u32 length, hi_u32 version);

/**
\brief Get antirollback version
\brief CNcomment ��ȡ���ع��汾�š� CNend
\attention \n
N/A
\param[in] addr:    OTP address.                       CNcomment:OTP ��ַ�� CNend
\param[in] length:  The length of otp.                 CNcomment:���ع��汾��OTP���ȡ� CNend
\param[out] version: antirollback version.             CNcomment:���ع��汾�š� CNend
\retval ::HI_SUCCESS  Call this API successful.         CNcomment:APIϵͳ���óɹ��� CNend
\retval ::HI_FAILURE  Call this API fails.              CNcomment:APIϵͳ����ʧ�ܡ� CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_verimatrix_get_anti_rollback_version(hi_u32 addr, hi_u32 length, hi_u32 *version);

/** @} */  /** <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif

