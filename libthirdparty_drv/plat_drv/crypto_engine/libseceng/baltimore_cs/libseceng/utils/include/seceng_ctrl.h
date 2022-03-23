/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: security engine control
 * Author     : m00475438
 * Create     : 2017/12/30
 */
#ifndef __SECENG_CTRL_H__
#define __SECENG_CTRL_H__
#include <common_define.h>
#include <common_utils.h>
#include <pal_log.h>

/* define FEATURE_SECENG_IP_CTRL_DEBUG */
#ifndef FEATURE_SECENG_IP_CTRL_DEBUG
#define SECENG_IP_ENTRY_TRACE() DO_NOTHING()
#define SECENG_IP_EXIT_TRACE() DO_NOTHING()
#else
#define SECENG_IP_ENTRY_TRACE() do { \
	PAL_PRINTF("\n"); \
	PAL_INFO("===> ENTRY\n"); \
} while (0)
#define SECENG_IP_EXIT_TRACE() do { \
	PAL_INFO("<=== EXIT\n"); \
	PAL_PRINTF("\n"); \
} while (0)
#endif /* FEATURE_SECENG_IP_CTRL_DEBUG */

#ifndef FEATURE_SECENG_IP_DYNAMIC_CTRL
#define SECENG_IP_ENTRY(pret, mid, ip_idx) do { \
	UNUSED(ip_idx); \
	*(pret) = BSP_RET_OK; \
} while (0)

#define SECENG_IP_EXIT(pret, mid, ip_idx) do { \
	UNUSED(ip_idx); \
	*(pret) = BSP_RET_OK; \
} while (0)

#define SECENG_IP_RUN(pret, mid, ip_idx, run_func) do { \
	UNUSED(ip_idx); \
	*(pret) = run_func; \
} while (0)

#define SECENG_IP_RUN_NO_RET(mid, ip_idx, run_func) do { \
	UNUSED(ip_idx); \
	run_func; \
} while (0)

#else
#define SECENG_IP_ENTRY(pret, mid, ip_idx) do { \
	UNUSED(*(pret)); \
	SECENG_IP_ENTRY_TRACE(); \
	*(pret) = seceng_power_vote(mid, ip_idx, SEC_ON); \
} while (0)

#define SECENG_IP_EXIT(pret, mid, ip_idx) do { \
	UNUSED(*(pret)); \
	*(pret) = seceng_power_vote(mid, ip_idx, SEC_OFF); \
	SECENG_IP_EXIT_TRACE(); \
} while (0)

#define SECENG_IP_RUN(pret, mid, ip_idx, run_func) do { \
	err_bsp_t __tmp_ret = ERR_DRV(ERRCODE_UNKNOWN); \
	SECENG_IP_ENTRY(pret, mid, ip_idx); \
	if (*(pret) == BSP_RET_OK) { \
		*(pret) = run_func; \
		SECENG_IP_EXIT(&__tmp_ret, mid, ip_idx); \
		if (*(pret) == BSP_RET_OK) \
			*(pret) = __tmp_ret; \
	} \
} while (0)

#define SECENG_IP_RUN_NO_RET(mid, ip_idx, run_func) do { \
			err_bsp_t __tmp_ret = ERR_DRV(ERRCODE_UNKNOWN); \
			SECENG_IP_ENTRY(&__tmp_ret, mid, ip_idx); \
			if (__tmp_ret == BSP_RET_OK) { \
				run_func; \
				SECENG_IP_EXIT(&__tmp_ret, mid, ip_idx); \
				UNUSED(__tmp_ret); \
			} \
		} while (0)

#endif /* FEATURE_SECENG_IP_DYNAMIC_CTRL */

#define SECENG_IP_MODULE_ENTRY(pret, ip_idx) \
	SECENG_IP_ENTRY(pret, BSP_THIS_MODULE, ip_idx)

#define SECENG_IP_MODULE_EXIT(pret, ip_idx) \
	SECENG_IP_EXIT(pret, BSP_THIS_MODULE, ip_idx)

#define SECENG_IP_MODULE_RUN(pret, ip_idx, run_func) \
	SECENG_IP_RUN(pret, BSP_THIS_MODULE, ip_idx, run_func)

/**
 * @brief      : engine function critical protection
 * @param[in]  : mid    module id
 * @param[in]  : ip_idx ip index
 * @param[in]  : onoff  ::SEC_ON is enable; other is disable
 */
err_bsp_t seceng_func_mutex_proc(u32 mid, u32 ip_idx, u32 onoff);

/**
 * @brief      : vote for engine ip on
 * @param[in]  : mid    module id
 * @param[in]  : ip_idx ip index
 * @param[in]  : onoff  ::SEC_ON is enable; other is disable
 */
err_bsp_t seceng_power_vote(u32 mid, u32 ip_idx, u32 onoff);

#endif /* end of __SECENG_CTRL_H__ */
