/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description:ecc curve fp2 process
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */
#ifndef __EC_FP2_SMPL_H__
#define __EC_FP2_SMPL_H__
#include <ec_curve.h>

#define POINT2_BN_SIZE  4

const struct ec_fp2_method *ec_fp2_simple_method(void);

struct ec_curve_group_fp2 *ec_group_fp2_new(void);

void ec_group_fp2_free(struct ec_curve_group_fp2 *fp2);

err_bsp_t ec_group_fp2_init_by_id(enum ecc_curve_id curve_id, struct ec_curve_group_fp2 *pcurve);

/* get curve parameter */
struct fp2_point_aff_cord *ec_group_fp2_get_generator(const struct ec_curve_group_fp2 *pcurve);

struct bn_data *ec_group_fp2_get_p(const struct ec_curve_group_fp2 *pcurve);

/* point init */
err_bsp_t fp2_point_init(struct fp2_point_aff_cord *pp);

void fp2_point_clearup(struct fp2_point_aff_cord *p);

err_bsp_t fp2_point_check(const struct fp2_point_aff_cord *pp);

err_bsp_t ec_curve_group_fp2_check(const struct ec_curve_group_fp2 *pcurve);

/**
 * @brief      : fp2_point_mul
 */
err_bsp_t fp2_point_mul(const struct ec_curve_group_fp2 *pcurve, const struct fp2_point_aff_cord *pp,
			const struct bn_data *pk, struct fp2_point_aff_cord *pr);

/**
 * @brief      : fp2_point_add
 */
err_bsp_t fp2_point_add(const struct ec_curve_group_fp2 *pcurve, const struct fp2_point_aff_cord *pp,
			const struct fp2_point_aff_cord *pq, struct fp2_point_aff_cord *pr);

/**
 * @brief      : ec_fp2_point_from_bin
 */
err_bsp_t ec_fp2_point_from_bin(const struct ec_curve_group_fp2 *pcurve, const u8 *pdata, u32 data_len,
				struct fp2_point_aff_cord *pr);

err_bsp_t ec_fp2_point_set_pdata(const struct ec_curve_group_fp2 *pcurve, u8 *pdata, u32 data_len,
				 struct fp2_point_aff_cord *pr);

/**
 * @brief      : ec_fp2_point_to_bin
 */
err_bsp_t ec_fp2_point_to_bin(const struct ec_curve_group_fp2 *pcurve, const struct fp2_point_aff_cord *pr,
			      u8 *pdata, u32 data_len);

#endif /* end of __EC_FP2_SMPL_H__ */
