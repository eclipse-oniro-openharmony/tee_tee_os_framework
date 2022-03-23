/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: engine control data type
 * Author     : m00475438
 * Create     : 2019/08/25
 */
#ifndef __COMMON_ENGCTRL_H__
#define __COMMON_ENGCTRL_H__

enum mspe_lcs {
	MSPE_LCS_ICCT    = 0x1E7887E1,
	MSPE_LCS_ICDT    = 0x376A1DC3,
	MSPE_LCS_UM      = 0x565F3E6A,
	MSPE_LCS_RMA     = 0x7B8A17A5,
	MSPE_LCS_SDM     = 0x9C31AF2B,
};

enum gm_smx {
	SMX_SM2 = 2,
	SMX_SM3 = 3,
	SMX_SM4 = 4,
};

#endif /* end of __COMMON_DEF_H__ */
