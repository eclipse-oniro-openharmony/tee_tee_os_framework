/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: HKDF is a simple key derivation function (KDF) based on
 *               a hash-based message authentication code (HMAC).
 * Author     : m00475438
 * Create     : 2020/02/06
 */
#ifndef __HISEE_HKDF_H__
#define __HISEE_HKDF_H__
#include <common_sce.h>

/**
 * brief       : To extract(condense/blend) entropy from a larger random source
 * @param[in]  : alg_type hash algorithm from enum symm_alg
 * @param[in]  : psalt    salt value acting as a key
 * @param[in]  : saltlen  salt bytes length
 * @param[in]  : pikm     any potentially weak input key material acting(IKM)
 * @param[in]  : ikmlen   input key material(IKM) bytes length
 * @param[out] : pprk     output pseudorandom key (PRK) buffer pointer
 * @param[io]  : pprklen  pseudorandom key (PRK) buffer bytes length
 */
err_bsp_t hisee_hkdf_extract(u32 alg_type,
			     const u8 *psalt, u32 saltlen,
			     const u8 *pikm, u32 ikmlen,
			     u8 *pprk, u32 *pprklen);

/**
 * brief       : To expand the generated output of an already reasonably random
 *               input such as an existing shared key into
 *               a larger cryptographically independent output
 * @param[in]  : alg_type hash algorithm from enum symm_alg
 * @param[in]  : pprk     pseudorandom key (PRK)
 * @param[in]  : prklen   pseudorandom key (PRK) bytes length
 * @param[in]  : pinfo    optional context string
 * @param[in]  : infolen  context string bytes length
 * @param[out] : pokm     output key material(OKM) buffer pointer
 * @param[in]  : okmlen   output key material(OKM) bytes length
 */
err_bsp_t hisee_hkdf_expand(u32 alg_type,
			    const u8 *pprk, u32 prklen,
			    const u8 *pinfo, u32 infolen,
			    u8 *pokm, u32 okmlen);

/**
 * brief       : hkdf extract and expand
 * @param[in]  : alg_type hash algorithm from enum symm_alg
 * @param[in]  : psalt    salt value acting as a key
 * @param[in]  : saltlen  salt bytes length
 * @param[in]  : pikm     any potentially weak input key material acting(IKM)
 * @param[in]  : ikmlen   input key material(IKM) bytes length
 * @param[in]  : pinfo    optional context string
 * @param[in]  : infolen  context string bytes length
 * @param[out] : pokm     output key material(OKM) buffer pointer
 * @param[in]  : okmlen   output key material(OKM) bytes length
 */
err_bsp_t hisee_hkdf_derive(u32 alg_type,
			    const u8 *psalt, u32 saltlen,
			    const u8 *pikm, u32 ikmlen,
			    const u8 *pinfo, u32 infolen,
			    u8 *pokm, u32 okmlen);
#endif /* __HISEE_HKDF_H__ */

