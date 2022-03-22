/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file is the header file of the otp driver.
 * Author: Hisilicon hisecurity group
 * Create: 2019-12-28
 */
#ifndef __HI_TEE_OTP_NAGRA_H__
#define __HI_TEE_OTP_NAGRA_H__

#include "hi_type_dev.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*************************** Structure Definition ****************************/
/** \addtogroup      OTP_NAGRA */
/** @{ */  /** <!-- [OTP_NAGRA] */

/** @} */  /** <!-- ==== Structure Definition end ==== */

/******************************* API declaration *****************************/
/** \addtogroup      OTP_NAGRA */
/** @{ */  /** <!-- [OTP_NAGRA] */

/**
\brief enable nagra privileged mode. CNcomment:使能nagra 特权模式 CNend
\attention \n
N/A
\retval::HI_SUCCESS Success                                                CNcomment:HI_SUCCESS 成功 CNend
\retval::HI_FAILURE This API fails to be called                            CNcomment:HI_FAILURE  API系统调用失败 CNend
\retval::HI_TEE_ERR_UNINITED The advanced OTP module is not initialized CNcomment:HI_TEE_ERR_UNINITED OTP未初始化 CNend
\retval::HI_TEE_ERR_INVALID_PARAM The input parameter value is invalid
\CNcomment:HI_TEE_ERR_INVALID_PARAM  输入参数非法 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_nagra_enable_privileged_mode(hi_void);

/**
\brief Get nagra privileged mode. CNcomment:获取nagra 权模式 CNend
\attention \n
N/A
\param[out]  privilege_mode Point to the privileged mode.                  CNcomment: 指针类型，获取特权模式CNend
\retval::HI_SUCCESS Success                                                CNcomment:HI_SUCCESS 成功 CNend
\retval::HI_FAILURE This API fails to be called                            CNcomment:HI_FAILURE  API系统调用失败 CNend
\retval::HI_TEE_ERR_UNINITED The advanced OTP module is not initialized CNcomment:HI_TEE_ERR_UNINITED OTP未初始化 CNend
\retval::HI_TEE_ERR_INVALID_PARAM The input parameter value is invalid
\CNcomment:HI_TEE_ERR_INVALID_PARAM  输入参数非法 CNend
\see \n
N/A
*/
hi_s32 hi_tee_otp_nagra_get_privileged_mode(hi_bool *privilege_mode);

/** @} */  /** <!-- ==== API declaration end ==== */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif

