/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description:hal sm9 process
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */
#ifndef __HAL_SM9_H__
#define __HAL_SM9_H__
#include <ec_curve.h>

err_bsp_t hal_sm9_init(void);

/**
 * @brief      : hal_sm9_rate
 * @param[in]  : pgroup sm9 paring group parameter
 * @param[in]  : pp point
 * @param[in]  : pq  2 field point
 * @param[out]  : pr  12 field result
 */
err_bsp_t hal_sm9_rate(const struct sm9_paring_group *pgroup,
		       const struct point_aff_cord *pp,
		       const struct fp2_point_aff_cord *pq,
		       fp12_bn pr);

/**
 * @brief      : hal_sm9_fp_point_mul
 * @param[in]  : pcurve ecc curve parameter
 * @param[in]  : pp point
 * @param[in]  : pk mult num
 * @param[out]  : pr result point
 */
err_bsp_t hal_sm9_fp_point_mul(const struct ec_curve_group_fp *pcurve,
			       const struct point_aff_cord *pp,
			       const struct bn_data *pk,
			       struct point_aff_cord *pr);

/**
 * @brief      : hal_sm9_fp_point_add
 * @param[in]  : pcurve ecc curve parameter
 * @param[in]  : pp  fp field point
 * @param[in]  : pq  fp field point
 * @param[out]  : pr result point
 */
err_bsp_t hal_sm9_fp_point_add(const struct ec_curve_group_fp *pcurve,
			       const struct point_aff_cord *pp,
			       const struct point_aff_cord *pq,
			       struct point_aff_cord *pr);

/**
 * @brief      : hal_sm9_fp2_point_mul
 * @param[in]  : pcurve fp2 field curve
 * @param[in]  : pp fp2 field point
 * @param[in]  : pk bn_data nult num
 * @param[out]  : pr fp2 field point result
 */
err_bsp_t hal_sm9_fp2_point_mul(const struct ec_curve_group_fp2 *pcurve,
				const struct fp2_point_aff_cord *pp,
				const struct bn_data *pk,
				struct fp2_point_aff_cord *pr);


/**
 * @brief      : hal_sm9_fp2_point_add
 * @param[in]  : pcurve fp2 field curve
 * @param[in]  : pp fp2 field point
 * @param[in]  : pq fp2 field point
 * @param[out]  : pr fp2 field point result
 */
err_bsp_t hal_sm9_fp2_point_add(const struct ec_curve_group_fp2 *pcurve,
				const struct fp2_point_aff_cord *pp,
				const struct fp2_point_aff_cord *pq,
				struct fp2_point_aff_cord *pr);

/**
 * @brief      : hal_sm9_fp12_mod_mul
 * @param[in]  : pgroup fp12 field group
 * @param[in]  : pa fp12 field data
 * @param[in]  : pb fp12 field data
 * @param[out]  : pr fp12 field data result
 */
err_bsp_t hal_sm9_fp12_mod_mul(const struct fp12_group *pgroup,
			       const fp12_bn pa,
			       const fp12_bn pb,
			       fp12_bn pr);

/**
 * @brief      : hal_sm9_fp12_mod_me
 * @param[in]  : pgroup fp12 field group
 * @param[in]  : pa fp12 field data
 * @param[in]  : pe bn_data pow
 * @param[out]  : pr fp12 field data reslut
 */
err_bsp_t hal_sm9_fp12_mod_me(const struct fp12_group *pgroup,
			      const fp12_bn pa,
			      const struct bn_data *pe,
			      fp12_bn pr);

/**
 * @brief      : hal_point_fp_is_on_curve
 * @param[in]  : pcurve ecc curve parameter
 * @param[in]  : pp prime field point
 * @note       : BSP_RET_OK:on cure
 */
err_bsp_t hal_point_fp_is_on_curve(const struct ec_curve_group_fp *pcurve,
				   const struct point_aff_cord *pp);

#endif /* end of __HAL_SM9_H__ */
