/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ec fp curve func
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */
#ifndef __EC_FP_SMPL_H__
#define __EC_FP_SMPL_H__
#include <ec_curve.h>

#define POINT_BN_SIZE  2

const struct ec_fp_method *ec_simple_method(void);    /* multi bitwidth */

const struct ec_fp_method *ec_fp_simple_method(void); /* 256 bitwidth */

struct ec_curve_group_fp *ec_group_fp_new(void);

void ec_group_fp_free(struct ec_curve_group_fp *fp);

err_bsp_t ec_group_fp_init_by_id(enum ecc_curve_id curve_id, struct ec_curve_group_fp *pcurve);

/* get curve parameter */
struct bn_data *ec_group_fp_get_p(const struct ec_curve_group_fp *pcurve);

struct bn_data *ec_group_fp_get_n_minus_one(const struct ec_curve_group_base *pcurve);

struct bn_data *ec_group_fp_get_modulus(const struct ec_curve_group_base *pcurve);

struct point_aff_cord *ec_group_fp_get_generator(const struct ec_curve_group_fp *pcurve);

err_bsp_t fp_point_init(struct point_aff_cord *pp);

void fp_point_clearup(struct point_aff_cord *p);

/* para check */
err_bsp_t fp_point_check(const struct point_aff_cord *pp);

err_bsp_t ec_curve_group_fp_check(const struct ec_curve_group_fp *pcurve);

/**
 * @brief      : fp_point_mul
 * @param[in]  : pcurve fp2 field curve
 * @param[in]  : pp fp2 field point
 * @param[in]  : pk bn_data nult num
 * @param[out]  : pr fp2 field point result
 */
err_bsp_t fp_point_mul(const struct ec_curve_group_fp *pcurve, const struct point_aff_cord *pp,
		       const struct bn_data *pk, struct point_aff_cord *pr);

/**
 * @brief      : fp_point_add
 * @param[in]  : pcurve ecc curve parameter
 * @param[in]  : pp  fp field point
 * @param[in]  : pq  fp field point
 * @param[out]  : pr result point
 */
err_bsp_t fp_point_add(const struct ec_curve_group_fp *pcurve, const struct point_aff_cord *pp,
		       const struct point_aff_cord *pq, struct point_aff_cord *pr);

/**
 * @brief      : ec_point_fp_is_on_curve
 * @param[in]  : pcurve ecc curve parameter
 * @param[in]  : pp prime field point
 * @note       : BSP_RET_OK:on cure
 */
err_bsp_t ec_point_fp_is_on_curve(const struct ec_curve_group_fp *pcurve, const struct point_aff_cord *pp);

/**
 * @brief      : ec_fp_point_from_bin
 * @param[in]  : pcurve ecc curve parameter
 * @param[in]  : pdata data change to point
 * @param[in]  : data_len data length
 * @param[out]  : pr point result
 */
err_bsp_t ec_fp_point_from_bin(const struct ec_curve_group_fp *pcurve, const u8 *pdata, u32 data_len,
			       struct point_aff_cord *pr);

err_bsp_t ec_fp_point_set_pdata(const struct ec_curve_group_fp *pcurve, u8 *pdata, u32 data_len,
				struct point_aff_cord *pr);

/**
 * @brief      : ec_fp_point_to_bin
 * @param[in]  : pcurve ecc curve parameter
 * @param[in]  : pr point change to data
 * @param[out]  : pdata data result
 * @param[out]  : data_len data result length
 */
err_bsp_t ec_fp_point_to_bin(const struct ec_curve_group_fp *pcurve, const struct point_aff_cord *pr,
			     u8 *pdata, u32 data_len);

#endif /* end of __EC_FP_SMPL_H__ */
