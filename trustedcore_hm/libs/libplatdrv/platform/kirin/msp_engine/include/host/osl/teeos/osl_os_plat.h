/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: os layer platform adapter
 * Author     : security-engine
 * Create     : 2020/05/03
 */
#ifndef __OSL_OS_PLAT_H__
#define __OSL_OS_PLAT_H__

#define OSA_NO_NEED_EVENT

enum osl_mutex_id {
	OSA_MUTEX_GATE_CLK,
	OSA_MUTEX_ECC_IP_LOCK,
	OSA_MUTEX_RSA_IP_LOCK,
	OSA_MUTEX_SM9_IP_LOCK,

	OSA_MUTEX_SYMM_IP_LOCK,
	OSA_MUTEX_SCE2_IP_LOCK,

	/* must be at the end */
	OSA_MUTEX_MAX,
};

#endif /* end of __OSL_OS_PLAT_H__ */
