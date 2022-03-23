/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ecc common api
 * Author     : Z00358830
 * Create     : 2019/08/10
 */

#ifndef __HISEE_ECC_COMMON_H__
#define __HISEE_ECC_COMMON_H__

#include <bn_basic.h>
#include <common_pke.h>
#include <standard_ecc.h>

/**
 * @note       : bn_init ,change the hisee_ecc_pubkey pubkey to hisee_ecc_pubkey_bn
 */
err_bsp_t hisee_ecc_pubkey2bndata(const struct hisee_ecc_pubkey *pkey,
				  struct hisee_ecc_pubkey_bn *pkey_bn);

/**
 * @note       : bn_init ,change the hisee_ecc_privkey to hisee_ecc_privkey_bn
 */
err_bsp_t hisee_ecc_privkey2bndata(const struct hisee_ecc_privkey *pkey,
				   struct hisee_ecc_privkey_bn *pkey_bn);

#endif /* end of __HISEE_ECC_COMMON_H__ */
