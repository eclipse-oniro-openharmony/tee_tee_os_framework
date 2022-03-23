/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: rsa key gen functions for hardware
 * Author     : h00401342
 * Create     : 2019/09/03
 * Note       : NA
 */

#ifndef __HAL_RSA_H__
#define __HAL_RSA_H__
#include <common_pke.h>
#include <bn_basic.h>
#include <standard_ecc.h>

/**
 * @brief      : input crt key e p q ,output std key d n
 * @param[in]  : width  bit width
 * @param[in]  : pe_in  public key
 * @param[in]  : pp_in  crt p
 * @param[in]  : pq_in  crt q
 * @param[in]  : pd_out std d
 * @param[in]  : pn_out std n
 * @note       :
 */
err_bsp_t hal_pke_crt2std(u32 width,
			  const struct bn_data *pe_in,
			  const struct bn_data *pp_in,
			  const struct bn_data *pq_in,
			  struct bn_data *pd_out,
			  struct bn_data *pn_out);

/**
 * @brief      : gen key with e
 * @param[in]  : width bit width
 * @param[in]  : pe public key
 * @param[in]  : pd_out std d
 * @param[in]  : pn_out std n
 * @note       :
 */
err_bsp_t hal_pke_genkey_e(u32 width,
			   const struct bn_data *pe,
			   struct bn_data *pd_out,
			   struct bn_data *pn_out);

/**
 * @brief      : gen key without e
 * @param[in]  : width bit width
 * @param[in]  : strategy 0: no enhanced other: enhanced
 * @param[in]  : pe_out public key
 * @param[in]  : pd_out std d
 * @param[in]  : pn_out std n
 * @note       :
 */
err_bsp_t hal_pke_genkey_ne(u32 width,
			    u32 strategy, struct bn_data *pe_out,
			    struct bn_data *pd_out, struct bn_data *pn_out);

/**
 * @brief      : rsa gen crtkey pq
 * @param[in]  : width bit width
 * @param[in]  : strategy 0: no enhanced other: enhanced
 * @param[in]  : pp_out big prime
 * @param[in]  : pq_out big prime
 * @note       :
 */
err_bsp_t hal_pke_genkey_pq(u32 width, u32 strategy, struct bn_data *pp_out,
			    struct  bn_data *pq_out);

#endif /* end of __HAL_RSA_H__ */
