/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: rsa test-related common data definitions
 * Author     : h00401342
 * Create     : 2019/08/08
 * Note       : NA
 */
#ifndef __COMMON_RSA_DFT_H__
#define __COMMON_RSA_DFT_H__
#include <bn_basic.h>

/**
 * @brief operation choice
 */
enum rsa_option_e {
	RSA_OPT_READ = 0,
	RSA_OPT_WRITE,
	RSA_OPT_READ_PRE, /* read key reg no mask post process */
};

/**
 * @brief ALARM type
 */
enum rsa_alarm_e {
	RSA_ALM_BAD_VAL     = (0),  /* invalid */
	RSA_ALM_BUSY        = (1),  /* write in calc */
	RSA_ALM_ORLDER      = (2),  /* config order error (p mul or mod_me) */
	RSA_ALM_LOCK        = (3),  /* reg lock */
	RSA_ALM_KEYLOCK     = (4),  /* KEY lock */
	RSA_ALM_BAK_ERR     = (5),  /* backup reg and reg diff */
};

struct rsa_mod_t {
	struct bn_data *pa;
	struct bn_data *pn;
	struct bn_data *pout;
	struct bn_data *pout_div;
};

struct rsa_mod_me_t {
	struct bn_data *pa;
	struct bn_data *pe;
	struct bn_data *pn;
	struct bn_data *pout;
};

#endif /* end of __COMMON_RSA_DFT_H__ */
