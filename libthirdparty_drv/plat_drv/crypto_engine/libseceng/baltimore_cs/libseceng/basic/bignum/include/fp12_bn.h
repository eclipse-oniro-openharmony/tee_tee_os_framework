/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description:fp12 bn data process
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */
#ifndef __FP12_BN_H__
#define __FP12_BN_H__
#include <fp4_bn.h>

#define FP12_SIZE      3
#define FP12_FIELD     12
#define FP12_TO_CONST  (struct bn_data * const (*)[FP2_SIZE][FP4_SIZE])

typedef fp4_bn fp12_bn[FP12_SIZE];

struct fp12_group {
	struct bn_data *pm;                // big prime number
	struct bn_data *ppoly[FP12_FIELD]; // the irreducible polynomial
	const struct group_fp12_method *pfun;
};

struct group_fp12_method {
	err_bsp_t (*mod_mul)(const struct fp12_group *, const fp12_bn, const fp12_bn, fp12_bn);

	err_bsp_t (*mod_me)(const struct fp12_group *,  const fp12_bn, const struct bn_data *, fp12_bn);
};

const struct group_fp12_method *group_fp12_simple_method(void);

err_bsp_t fp12_group_init(struct bn_data *pp,
			  struct bn_data **ppoly,
			  u32 poly_len,
			  struct fp12_group *pgroup);

err_bsp_t fp12_init(fp12_bn pp);

void fp12_clearup(fp12_bn in);

err_bsp_t fp12_mod_mul(const struct fp12_group *pgroup,
		       const fp12_bn pa,
		       const fp12_bn pb,
		       fp12_bn pr);

err_bsp_t fp12_mod_me(const struct fp12_group *pgroup,
		      const fp12_bn pa,
		      const struct bn_data *pe,
		      fp12_bn pr);
/**
 * @brief      : copy pfrom data to bn pdata
 */
err_bsp_t fp12_from_bin(fp12_bn pto, const u8 *pfrom, u32 from_len, u32 width);

/**
 * @brief      : pfrom point to bn pdata
 */
err_bsp_t fp12_set_pdata(fp12_bn pto, u8 *pfrom, u32 from_len, u32 width);

err_bsp_t fp12_to_bin(const fp12_bn pfrom, u8 *pto, u32 to_len, u32 width);

err_bsp_t f12_group_check(const struct fp12_group *pgroup);

err_bsp_t f12_bn_check(const fp12_bn pfp12);

#endif /* end of __FP12_BN_H__ */
