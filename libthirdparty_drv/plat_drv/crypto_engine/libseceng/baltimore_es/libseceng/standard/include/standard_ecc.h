/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: ECC  standard protocol common function
 * Author     : h00401342
 * Create     : 2019/09/03
 */
 #ifndef __STANDARD_ECC_BASIC__
 #define __STANDARD_ECC_BASIC__
 #include <bn_basic.h>
 #include <ec_curve.h>
 #include <common_ecc.h>

/**
 * @brief ECC curve parameter bn struct
 */
struct ecc_curve_bn {
	u32     width;         /* ECC standard width?ecc_keywidth_std */
	struct bn_data *pp;    /* correspond to ECC curve parameter P */
	struct bn_data *pa;    /* correspond to ECC curve parameter a */
	struct bn_data *pb;    /* correspond to ECC curve parameter b */
	struct bn_data *pn;    /* correspond to ECC curve parameter n  */
	struct bn_data *pgx;   /* correspond to ECC curve parameter gx */
	struct bn_data *pgy;   /* correspond to ECC curve parameter gy */
};

struct hisee_ecc_privkey_bn {
	enum ecc_curve_id curve_id;
	u32 width;
	struct bn_data priv;
};

struct hisee_ecc_pubkey_bn {
	enum ecc_curve_id curve_id;
	u32 width;
	struct bn_data pubx;
	struct bn_data puby;
};

struct hisee_ecc_keypair_bn {
	enum ecc_curve_id curve_id;
	u32 width;
	struct bn_data priv;
	struct bn_data pubx;
	struct bn_data puby;
};

/**
 * @brief      : ECC data in [1,n-1]
 * @param[in]  : pn mod N
 * @param[in]  : pd data
 * @note       :suppose NULL is checked
 */
err_bsp_t ecc_check_domain(const struct bn_data *pn, const struct bn_data *pd);

/**
 * @brief      : ECC curve para check
 * @param[in]  : pcurve_s curve para
 */
err_bsp_t ecc_check_curve(const struct ec_curve_group_fp *pcurve_s);

/**
 * @brief      :  key check
 * @param[in]  : key_e    key type
 * @param[in]  : pkey_s    key
 * @param[in]  : pcurve_s  ECC curve para
 * @note       : suppose NULL is checked
 */
err_bsp_t ecc_check_keypair(struct hisee_ecc_keypair_bn *pkey_s,
			    const struct ec_curve_group_fp *pcurve_s);

err_bsp_t ecc_check_privkey(struct hisee_ecc_privkey_bn *pkey_s,
			    const struct ec_curve_group_fp *pcurve_s);

err_bsp_t ecc_check_pubkey(struct hisee_ecc_pubkey_bn *pkey_s,
			   const struct ec_curve_group_fp *pcurve_s);

/**
 * @brief      : check point is on curve
 * @param[in]  : pcurve_s curve papra
 * @param[in]  : presult point
 * @note       : y^2==x^3+ax+b
 *               suppose NULL is checked
 */
err_bsp_t ecc_check_point(const struct ec_curve_group_fp *pcurve_s,
			  const struct point_aff_cord *presult);

err_bsp_t ecc_curve_transform(struct ecc_curve_bn *pcurve_bn, struct ec_curve_group_fp *pcurve_s);

err_bsp_t ecc_point_transform(struct point *ppoint, struct point_aff_cord *ppoint_aff);
#endif

