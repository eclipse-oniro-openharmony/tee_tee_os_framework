/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  functions for hardware
 * Author     : h00401342
 * Create     : 2018/02/24
 * Note       :
 */
#ifndef __HAL_POINT_H__
#define __HAL_POINT_H__
#include <common_pke.h>
#include <standard_ecc.h>

/**
 * @brief      : point add
 * @param[in]  : pcurve_s point to parameter of curve
 * @param[in]  : pa point to point a
 * @param[in]  : pb point to point b
 * @param[in]  : pout point to point add result
 * @note       :
 *             : width is ecc standard width 521 192 384 256,
 *             : parameter buffer size same
 *             : size is (width / 8)  * 8 +8
 */
err_bsp_t hal_pke_point_add(const struct ecc_curve_bn *pcurve_s,
			    const struct point *pa,
			    const struct point *pb,
			    struct  point *pout);

/**
 * @brief      : point multiplys
 * @param[in]  : pcurve_s  point to parameter of curve
 * @param[in]  : pmul_k point to point multiply coefficient
 * @param[in]  : pin point to point
 * @param[in]  : pout point to point multiply result
 * @note       :
 *             : width is ecc standard width 521 192 384 256,
 *             : parameter buffer size same
 *             : size is (width / 8)  * 8 +8
 */
err_bsp_t hal_pke_point_mul(const struct ecc_curve_bn *pcurve_s,
			    const struct bn_data *pmul_k,
			    const struct point *pin,
			    struct point *pout);


err_bsp_t hal_point_mul(const struct ec_curve_group_fp *pcurve_s, const struct point_aff_cord *pin,
			const struct bn_data *pmul_k, struct point_aff_cord *pout);

err_bsp_t hal_point_add(const struct ec_curve_group_fp *pcurve_s, const struct point_aff_cord *pa,
			const struct point_aff_cord *pb, struct point_aff_cord *pout);

#endif /* end of __HAL_POINT_H__ */
