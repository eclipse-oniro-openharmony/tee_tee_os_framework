/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: common structure
 * Author     : h00401342
 * Create     : 2019/08/20
 * Note       :
 */

#ifndef __COMMON_BN_DFT_H__
#define __COMMON_BN_DFT_H__
#include <bn_basic.h>

#define HAT_FLAGS_NEW  0x0
#define HAT_FLAGS_INIT 0x1

/**
 * @brief big number data structure
 */
struct test_bn_data {
	u8      *pdata; /* point to data buffer */
	u32     size;   /* allocated buffer size unit:byte */
	u32     flags;  /* 0: test_bn_new 1:bn_init */
};

/**
 * @brief ECC curve parameter bn struct
 */
struct test_ecc_curve_bn {
	u32     width;          /* ECC standard width?ecc_keywidth_std */
	struct test_bn_data *pp;    /* correspond to ECC curve parameter P */
	struct test_bn_data *pa;    /* correspond to ECC curve parameter a */
	struct test_bn_data *pb;    /* correspond to ECC curve parameter b */
	struct test_bn_data *pn;    /* correspond to ECC curve parameter n  */
	struct test_bn_data *pgx;   /* correspond to ECC curve parameter gx */
	struct test_bn_data *pgy;   /* correspond to ECC curve parameter gy */
};

enum hat_bn_type {
	HAT_BN_MOD            = 0,
	HAT_BN_MOD_ADD        = 1,
	HAT_BN_MOD_SUB        = 2,
	HAT_BN_MOD_MUL_MM     = 3,
	HAT_BN_MOD_MUL_NORMAL = 4,
	HAT_BN_MOD_INV_MM     = 5,
	HAT_BN_MOD_INV_NORMAL = 6,
	HAT_BN_ADD            = 7,
	HAT_BN_SUB            = 8,
	HAT_BN_MUL            = 9,
	HAT_BN_DIV            = 10,
	HAT_BN_MM_TO_NORMAL   = 11,
	HAT_BN_NORMAL_TO_MM   = 12,
	HAT_BN_MOD_ME         = 13,
};

enum hat_rsa_type {
	HAT_RSA_MOD            = 0,
	HAT_RSA_MOD_ADD        = 1,
	HAT_RSA_MOD_SUB        = 2,
	HAT_RSA_MOD_MUL_MM     = 3,
	HAT_RSA_MOD_INV_MM     = 4,
	HAT_RSA_MUL            = 5,
	HAT_RSA_MOD_ME         = 6,
	HAT_RSA_DIV            = 7,
};

enum hat_ecc_type {
	HAT_ECC_MOD_ADD        = 0,
	HAT_ECC_MOD_SUB        = 1,
	HAT_ECC_MOD_MUL_NORMAL = 2,
	HAT_ECC_MOD_INV_NORMAL = 3,

};
#endif /* end of __COMMON_BN_DFT_H__ */
