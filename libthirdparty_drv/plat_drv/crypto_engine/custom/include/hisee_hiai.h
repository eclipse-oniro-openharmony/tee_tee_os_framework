/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hiai special function interface
 * Author: security-engine
 * Create: 2020/04/20
 */

#ifndef __HISEE_HIAI_H__
#define __HISEE_HIAI_H__
#include <common_km.h>
#include <common_sce.h>
#include <common_ecc.h>

enum hisee_hiai_verify {
	HIAI_VERIFY_SHA256,
};

struct hisee_hiai_data {
	enum symm_alg           alg;       /* algorithm for ecc key decrypt */
	enum symm_mode          mode;      /* algorithm mode */
	enum symm_ktype         keytype;   /* key type for derive eg.GID */
	enum hisee_hiai_verify  vtype;     /* ecc private verify algorithm */
	struct basic_data       vvalue;    /* verify value */
	struct basic_data       iv;        /* iv for ecc privkey decrypt */
	struct basic_data       derivein;  /* material for derive (16 + 16) */
	struct hisee_ecc_pubkey pubkey;    /* ecdh pub key gen by hiai tool */
};

/**
 * @brief      : hiai key compute
 * @param[in]  : pdata    hiai data information from ::struct hisee_hiai_data
 * @param[in]  : pdin     ecc private key ciphertext
 * @param[in]  : dinlen   key ciphertext bytes length
 * @param[out] : pdout    output buffer for hiai key compute
 * @param[in]  : doutlen  output key bytes length
 */
err_bsp_t hisee_hiai_key_compute(const struct hisee_hiai_data *pdata,
				 const u8 *pdin, u32 dinlen,
				 u8 *pdout, u32 doutlen);

#endif /* end of __HISEE_HIAI_H__ */
