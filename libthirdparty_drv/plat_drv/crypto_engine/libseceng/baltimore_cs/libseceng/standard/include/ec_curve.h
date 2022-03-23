/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ecc curve struct define
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */
#ifndef __EC_CURVE_H__
#define __EC_CURVE_H__
#include <fp12_bn.h>
#include <common_ecc.h>
#include <common_pke.h>

struct point_prj_cord {
	struct bn_data *px;
	struct bn_data *py;
	struct bn_data *pz;
};

struct fp2_point_aff_cord {
	fp2_bn px;
	fp2_bn py;
};

struct fp12_point_aff_cord {
	fp12_bn x;
	fp12_bn y;
};

struct ec_curve_group_base {
	enum ecc_curve_id curve_id;
	u32 width;
	struct bn_data *pa;
	struct bn_data *pb;
	struct bn_data *pn;
	struct bn_data *pseed;
	u32 h;
};

struct ec_curve_group_fp {
	struct ec_curve_group_base *pbase;
	struct bn_data *pp;
	struct point_aff_cord *pgenerator;
	const struct ec_fp_method *pfun;
};

struct ec_curve_group_fp2 {
	struct ec_curve_group_base *pbase;
	struct bn_data *pm;               // Field specification
	struct bn_data *ppoly[FP2_FIELD]; // the irreducible polynomial
	struct fp2_point_aff_cord *pgenerator;
	const struct ec_fp2_method *pfun;
};

struct ec_fp_method {
	/* group func */
	err_bsp_t (*group_init_by_id)(enum ecc_curve_id,
				      struct ec_curve_group_fp *);
	struct bn_data *(*group_get_order)(const struct ec_curve_group_base *);
	struct bn_data *(*group_get_order_minus_one)(const struct ec_curve_group_base *);
	struct bn_data *(*group_get_p)(const struct ec_curve_group_fp *);
	struct point_aff_cord *(*group_get_generator)(const struct ec_curve_group_fp *);

	/* point func */
	err_bsp_t (*point_new)(struct point_aff_cord *);
	void (*point_free)(struct point_aff_cord *);
	err_bsp_t (*point_mul)(const struct ec_curve_group_fp *, const struct point_aff_cord *,
			       const struct bn_data *, struct point_aff_cord *);
	err_bsp_t (*point_add)(const struct ec_curve_group_fp *, const struct point_aff_cord *,
			       const struct point_aff_cord *, struct point_aff_cord *);
	err_bsp_t (*point_is_on_curve)(const struct ec_curve_group_fp *, const struct point_aff_cord *);
	err_bsp_t (*point_from_bin)(const struct ec_curve_group_fp *, const u8 *, u32, struct point_aff_cord *);
	err_bsp_t (*point_to_bin)(const struct ec_curve_group_fp *, const struct point_aff_cord *, u8 *, u32);
	err_bsp_t (*point_set_pdata)(const struct ec_curve_group_fp *, u8 *, u32, struct point_aff_cord *);

};

struct ec_fp2_method {
	/* group func */
	err_bsp_t (*group_init_by_id)(enum ecc_curve_id, struct ec_curve_group_fp2 *);
	struct bn_data *(*group_get_order)(const struct ec_curve_group_base *);
	struct bn_data *(*group_get_order_minus_one)(const struct ec_curve_group_base *);
	struct bn_data *(*group_get_p)(const struct ec_curve_group_fp2 *);
	struct fp2_point_aff_cord *(*group_get_generator)(const struct ec_curve_group_fp2 *);

	/* point func */
	err_bsp_t (*point_new)(struct fp2_point_aff_cord *);
	void (*point_free)(struct fp2_point_aff_cord *);
	err_bsp_t (*point_mul)(const struct ec_curve_group_fp2 *, const struct fp2_point_aff_cord *,
			       const struct bn_data *, struct fp2_point_aff_cord *);
	err_bsp_t (*point_add)(const struct ec_curve_group_fp2 *, const struct fp2_point_aff_cord *,
			       const struct fp2_point_aff_cord *, struct fp2_point_aff_cord *);
	err_bsp_t (*point_from_bin)(const struct ec_curve_group_fp2 *, const u8 *, u32, struct fp2_point_aff_cord *);
	err_bsp_t (*point_to_bin)(const struct ec_curve_group_fp2 *, const struct fp2_point_aff_cord *, u8 *, u32);
	err_bsp_t (*point_set_pdata)(const struct ec_curve_group_fp2 *, u8 *, u32, struct fp2_point_aff_cord *);
};

struct ec_fp_list_element {
	enum ecc_curve_id curve_id;
	u32 width;
	u32 h;
	struct bn_data *pa;
	struct bn_data *pb;
	struct bn_data *pn;
	struct bn_data *pn_minus_one;
	struct bn_data *pseed;
	struct bn_data *pp;
	struct bn_data *pgx;
	struct bn_data *pgy;
	const struct ec_fp_method *(*meth)(void);
};

struct ec_fp2_list_element {
	enum ecc_curve_id curve_id;
	u32 width;
	u32 h;
	struct bn_data *pa;
	struct bn_data *pb;
	struct bn_data *pn;
	struct bn_data *pn_minus_one;
	struct bn_data *pseed;
	struct bn_data *pp;
	struct bn_data *ppoly[FP2_FIELD];
	struct bn_data *pgx1;
	struct bn_data *pgx0;
	struct bn_data *pgy1;
	struct bn_data *pgy0;
	const struct ec_fp2_method *(*meth)(void);
};

struct sm9_paring_group {
	struct ec_curve_group_fp  *pg1; // prime field group
	struct ec_curve_group_fp2 *pg2; // fp2 field group
	struct fp12_group         *pgt; // fp12 field group
	err_bsp_t (*paring)(const struct sm9_paring_group *, const struct point_aff_cord *,
			    const struct fp2_point_aff_cord *, fp12_bn);
};

typedef err_bsp_t (*sm9_paring)(const struct sm9_paring_group *, const struct point_aff_cord *,
				const struct fp2_point_aff_cord *, fp12_bn);

const struct ec_fp2_list_element *ec_get_fp2element_by_id(enum ecc_curve_id);

const struct ec_fp_list_element *ec_get_fpelement_by_id(enum ecc_curve_id);

u32 ec_get_width_by_id(enum ecc_curve_id curve_id);

#endif /* end of __EC_CURVE_H__ */
