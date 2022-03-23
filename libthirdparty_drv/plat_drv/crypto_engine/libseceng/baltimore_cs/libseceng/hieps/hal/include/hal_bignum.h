/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: big num mod functions for hardware
 * Author     : h00401342
 * Create     : 2019/09/03
 * Note       :NA
 */
#ifndef __HAL_BIGMUM_H__
#define __HAL_BIGMUM_H__
#include <common_pke.h>
#include <bn_basic.h>

/**
 * @brief      : input a n ,output a mod n and a / n
 */
err_bsp_t hal_pke_mod(const struct bn_data *pa, const struct bn_data *pn,
		      struct bn_data *pout, struct bn_data *pout_div);

/**
 * @brief      : input a b n ,output (a + b) mod n
 */
err_bsp_t hal_pke_mod_add(const struct bn_data *pa,
			  const struct bn_data *pb,
			  const struct bn_data *pn,
			  struct bn_data *pout);

/**
 * @brief      : input a b n ,output (a - b) mod n
 */
err_bsp_t hal_pke_mod_sub(const struct bn_data *pa,
			  const struct bn_data *pb,
			  const struct bn_data *pn,
			  struct bn_data *pout);

/**
 * @brief      : input a b n ,output (a * b) mod n
 */
err_bsp_t hal_pke_mod_mul(const struct bn_data *pa,
			  const struct bn_data *pb,
			  const struct bn_data *pn,
			  struct bn_data *pout);

/**
 * @brief      : input a e n ,output (a ^ e) mod n
 */
err_bsp_t hal_pke_mod_me(const struct bn_data *pa,
			 const struct bn_data *pe,
			 const struct bn_data *pn,
			 struct bn_data *pout);

/**
 * @brief      : input a n ,output (a ^ (-1)) mod n
 */
err_bsp_t hal_pke_mod_inv(const struct bn_data *pa,
			  const struct bn_data *pn,
			  struct bn_data *pout);

/**
 * @brief      : input a b ,output a*b
 */
err_bsp_t hal_pke_bn_mul(const struct bn_data *pa, const struct bn_data *pb,
			 struct bn_data *pout);

#endif /* end of __HAL_BIGMUM_H__ */
