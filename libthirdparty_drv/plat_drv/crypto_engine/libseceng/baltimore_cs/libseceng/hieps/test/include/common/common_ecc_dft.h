/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  ecc test-related common data definitions
 * Author     : h00401342
 * Create     : 2019/08/08
 * Note       : NA
 */
#ifndef __COMMON_ECC_DTF_H__
#define __COMMON_ECC_DTF_H__

/**
 * @brief operation choice
 */
enum ecc_option_e {
	ECC_OPT_READ = 0,
	ECC_OPT_WRITE,
	ECC_OPT_READ_PRE, /* read old value before mask */
};

/**
 * @brief ALARM type
 */
enum ecc_alarm_e {
	ECC_ALM_BAD_VAL     = (0),  /* invalid */
	ECC_ALM_POINTER     = (1),  /* invalid curve point */
	ECC_ALM_LOCK        = (2),  /* reg lock */
	ECC_ALM_KEYLOCK     = (3),  /* KEY lock */
	ECC_ALM_BAK_ERR     = (4),  /* backup reg and reg diff */
	ECC_ALM_SCRAMB      = (5),  /* enable scramb write reg */
};

struct ecc_point_mul_t {
	struct bn_data *pmul_k;
	struct point *pin;
	struct point *pout;
};

struct ecc_point_add_t {
	struct point *pa;
	struct point *pb;
	struct point *pout;
};

#endif /* end of __COMMON_ECC_DTF_H__ */
