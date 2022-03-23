/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: custom hiai inner func
 * Author     : security-engine
 * Create     : 2020/04/20
 */
#ifndef __HISEE_HIAI_INNER__
#define __HISEE_HIAI_INNER__
#include <hisee_hiai.h>
#include <hieps_errno.h>
#include <hieps_power.h>
#include <common_define.h>
#include <common_utils.h>
#include <pal_log.h>

#define SECENG_HIAI_RUN(pret, run_func) do { \
	uint32_t __tmp_ret = HIEPS_ERROR;\
	__tmp_ret = hieps_power_on(HIAI, PROFILE_080V); \
	if (PAL_CHECK(__tmp_ret != HIEPS_OK)) { \
		PAL_PRINTF("mspe:hiai poweron failed: 0x%x!\n", __tmp_ret); \
		*(pret) = ERR_API(ERRCODE_SYS); \
	} else { \
		*(pret) = run_func; \
		__tmp_ret = hieps_power_off(HIAI, PROFILE_080V); \
		if (PAL_CHECK(__tmp_ret != HIEPS_OK)) \
			PAL_PRINTF("mspe:hiai poweroff failed: 0x%x!\n", __tmp_ret); \
	} \
} while (0)

#ifdef FEATURE_DFT_ENABLE
err_bsp_t hisee_hiai_key_derive(const struct hisee_hiai_data *pdata,
				u8 *pdout, u32 *pdoutlen);

err_bsp_t hisee_hiai_key_decrypt(const struct hisee_hiai_data *pdata,
				 const u8 *pkey, u32 keylen,
				 const u8 *pdin, u32 dinlen,
				 u8 *pdout, u32 *pdoutlen);

err_bsp_t hisee_hiai_key_verify(const struct hisee_hiai_data *pdata,
				const u8 *pkey, u32 keylen);

err_bsp_t hisee_hiai_ecdh_compute(const struct hisee_ecc_pubkey *ppubkey,
				  const u8 *privkey, u32 keylen,
				  u8 *pdout, u32 doutlen);
#endif /*FEATURE_DFT_ENABLE*/

#endif /* __HISEE_HIAI_INNER__ */
