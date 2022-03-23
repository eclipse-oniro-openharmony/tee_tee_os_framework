/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: seceng flow control interface
 * Author     : m00475438
 * Create     : 2017/12/30
 */
#ifndef __SECENG_FLOWCTRL_H__
#define __SECENG_FLOWCTRL_H__
#include <pal_log.h>

/**
 * @brief flow ctrl step
 */
enum sec_fc_step_e {
	SEC_FC_STEP1 = 1,
	SEC_FC_STEP2,
	SEC_FC_STEP3,
	SEC_FC_STEP4,
	SEC_FC_STEP5,
	SEC_FC_STEP6,
	SEC_FC_STEP7,
	SEC_FC_STEP8,
	SEC_FC_STEP9,
	SEC_FC_STEP10,
	SEC_FC_STEP11,
	SEC_FC_STEP12,
	SEC_FC_STEP13,
	SEC_FC_STEP14,
	SEC_FC_STEP15,
	SEC_FC_STEP16,
	SEC_FC_STEP17,
	SEC_FC_STEP18,
	SEC_FC_STEP19,
	SEC_FC_STEP20,
};

struct sec_fc_data {
	err_bsp_t ret;
	uintptr_t counter;
};

#ifdef FEATURE_SEC_FC_SIMPLE
#define FC_VOLATILE
#else
#define FC_VOLATILE volatile
#endif /* FEATURE_SEC_FC_SIMPLE */

#define SEC_FC_INIT() \
	FC_VOLATILE struct sec_fc_data __fc = {ERR_DRV(ERRCODE_ATTACK), 0}

#define SEC_FC_STEP_CHECK(step, pout_ret, cur_ret) \
	(PAL_CHECK((((__fc.ret = (cur_ret)) != BSP_RET_OK) ? \
		   (*(pout_ret) = __fc.ret) : \
		   ((__fc.counter += __fc.ret) != ((step) * BSP_RET_OK)) ? \
		   (*(pout_ret) = ERR_DRV(ERRCODE_ATTACK)) : \
		   __fc.ret) != BSP_RET_OK))

#define SEC_FC_FINAL_CHECK(total_steps, pout_ret, cur_ret) \
	(PAL_CHECK((((__fc.ret = (cur_ret)) != BSP_RET_OK) ? \
		(*(pout_ret) = __fc.ret) : \
		((__fc.counter += __fc.ret) != ((total_steps) * BSP_RET_OK)) ? \
		(*(pout_ret) = ERR_DRV(ERRCODE_ATTACK)) : \
		(*(pout_ret) = __fc.ret)) != BSP_RET_OK))

#define SEC_FC_FINAL_RET(total_steps) \
	(((__fc.counter / (total_steps)) == BSP_RET_OK) ? \
	 BSP_RET_OK : ERR_DRV(ERRCODE_ATTACK))

#endif /* __SECENG_FLOWCTRL_H__ */
