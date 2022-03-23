/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: basic big number arithmetic library
 * Author     : h00401342
 * Create     : 2019/09/03
 * Note       : NA
 */
#ifndef __BN_BASIC_H__
#define __BN_BASIC_H__
#include <common_pke.h>

/**
 * @brief big number data structure
 */
struct bn_data {
	u8      *pdata; /* point to data buffer */
	u32     size;   /* allocated buffer size unit:byte */
	u32     length; /* data valid length unit:u8 */
	u32     flags;  /* flag data is BN malloc */
};

enum bn_flags {
	BN_FLAGS_MALLOCED      = 0x0,
	BN_FLAGS_STATIC        = 0x1,
	BN_FLAGS_SECURE        = 0x3,
};

/**
 * @brief      : input a n ,output a mod n
 * @param[in]  : pa
 * @param[in]  : pn
 * @param[in]  : pout
 */
err_bsp_t bn_mod(const struct bn_data *pa, const struct bn_data *pn,
		 struct bn_data *pout);

/**
 * @brief      : input a b n ,output (a + b) mod n
 * @param[in]  : pa
 * @param[in]  : pb
 * @param[in]  : pn
 * @param[in]  : pout
 */
err_bsp_t bn_mod_add(const struct bn_data *pa, const struct bn_data *pb,
		     const struct bn_data *pn, struct bn_data *pout);

/**
 * @brief      : input a b n ,output (a - b) mod n
 * @param[in]  : pa
 * @param[in]  : pb
 * @param[in]  : pn
 * @param[in]  : pout
 */
err_bsp_t bn_mod_sub(const struct bn_data *pa, const struct bn_data *pb,
		     const struct bn_data *pn, struct bn_data *pout);

/**
 * @brief      : input a b n ,output (a * b) mod n
 * @param[in]  : pa point to multiplicand a
 * @param[in]  : pb point to multiplier b
 * @param[in]  : pn point to modulus n
 * @param[in]  : pout point to multiplier b
 * @note       : suppose data is montgomery
 */
err_bsp_t bn_mod_mul_montgomery(const struct bn_data *pa,
				const struct bn_data *pb,
				const struct bn_data *pn,
				struct bn_data *pout);

/**
 * @brief      : input a b n ,output (a * b) mod n
 * @param[in]  : pa point to multiplicand a
 * @param[in]  : pb point to multiplier b
 * @param[in]  : pn point to modulus n
 * @param[in]  : pout point to result of (a - b) mod n
 * @note       :
 */
err_bsp_t bn_mod_mul(const struct bn_data *pa,
		     const struct bn_data *pb,
		     const struct bn_data *pn,
		     struct bn_data *pout);

/**
 * @brief      : input a e n ,output (a ^ e) mod n
 * @param[in]  : pa point to base number a
 * @param[in]  : pe point to  power exponent e
 * @param[in]  : pn point to modulus n
 * @param[in]  : pout point to result of (a ^ e) mod n
 */
err_bsp_t bn_mod_me(const struct bn_data *pa, const struct bn_data *pe,
		    const struct bn_data *pn, struct bn_data *pout);

/**
 * @brief      : input a n ,output (a ^ (-1)) mod n
 * @param[in]  : pa point to dividend a
 * @param[in]  : pn point to modulus n
 * @param[in]  : pout point to result of (a ^ e) mod n
 * @note       : suppose data is montgomery
 */
err_bsp_t bn_mod_inv_montgomery(const struct bn_data *pa,
				const struct bn_data *pn,
				struct bn_data *pout);

/**
 * @brief      : input a n ,output (a ^ (-1)) mod n
 * @param[in]  : pa point to dividend a
 * @param[in]  : pn point to modulus n
 * @param[in]  : pout point to result of (a ^ (-1)) mod n
 * @note       :
 */
err_bsp_t bn_mod_inv(const struct bn_data *pa,
		     const struct bn_data *pn,
		     struct bn_data *pout);

/**
 * @brief      : input a b ,output a+b
 * @param[in]  : pa point to summand a
 * @param[in]  : pb point to addend b
 * @param[in]  : pout point to result of a+b
 */
err_bsp_t bn_add(const struct bn_data *pa, const struct bn_data *pb,
		 struct bn_data *pout);

/**
 * @brief      : input a b ,output a-b
 * @param[in]  : pa point to minuend a
 * @param[in]  : pb point to subtrahend b
 * @param[in]  : pout point to result of a-b
 */
err_bsp_t bn_sub(const struct bn_data *pa, const struct bn_data *pb,
		 struct bn_data *pout);

/**
 * @brief      : input a b ,output a*b
 * @param[in]  : pa point to multiplicand a
 * @param[in]  : pb point to multiplier b
 * @param[in]  : pout point to result of a*b
 */
err_bsp_t bn_mul(const struct bn_data *pa, const struct bn_data *pb,
		 struct bn_data *pout);

/**
 * @brief      : input a b ,output a/b
 * @param[in]  : pa point to dividend a
 * @param[in]  : pb point to divisor b
 * @param[in]  : pout point to result of a/b
 * @note       :
 */
err_bsp_t bn_div(const struct bn_data *pa, const struct bn_data *pb,
		 struct bn_data *pout);

/**
 * @brief      : change data from Montgomery to normal
 * @param[in]  : pin_mm point to Montgomery
 * @param[in]  : pmodulo_n point to modulus n
 * @param[in]  : pout_normal point to result of normal
 */
err_bsp_t bn_mm_to_normal(const struct bn_data *pin_mm,
			  const struct bn_data *pmodulo_n,
			  struct bn_data *pout_normal);

/**
 * @brief      : change data from normal to Montgomery
 * @param[in]  : pin_normal point to normal
 * @param[in]  : pmodulo_n point to modulus n
 * @param[in]  : pout_mm point to result of Montgomery
 */
err_bsp_t bn_normal_to_mm(const struct bn_data *pin_normal,
			  const struct bn_data *pmodulo_n,
			  struct bn_data *pout_mm);

/**
 * @brief      : compare a and b sec_bignum_cmp
 * @param[in]  : pa point to comparand a
 * @param[in]  : pb point to comparand b
 * @note       :int compare result 0:a=b 1:a>b -1:a<b
 */
int bn_compare(const struct bn_data *pa, const struct bn_data *pb);

/**
 * @brief      : change input data to needed clear width high bit to 0
 * @param[in]  : pa point to inputdata
 * @param[in]  : bitwidth output valid width
 */
err_bsp_t bn_set_bitwidth(struct bn_data *pa, u32 bitwidth);

/**
 * @brief      : set bn data to value
 * @param[in]  : pbn point to inputdata
 * @param[in]  : value
 */
err_bsp_t bn_set_value(struct bn_data *pbn, u8 value);

/**
 * @brief      : change data to struct bn_data
 * @param[in]  : pbn point to struct bn_data
 * @param[in]  : data
 * @param[in]  : size
 * @note       :
 */
err_bsp_t bn_init(struct bn_data *pbn, u8 *data, u32 size);

err_bsp_t bn_check_clean(struct bn_data *pbn, u8 *data);

err_bsp_t bn_clean(struct bn_data *pbn);

/**
 * @brief      : malloc bn_data
 */
struct bn_data *bn_new(void);

/**
 * @brief      : free bn_data
 */
void bn_free(struct bn_data *pbn);

/**
 * @brief      : bn_data data set zero
 */
err_bsp_t bn_set_all_zero(struct bn_data *pa);

/**
 * @brief      : get constant one
 */
const struct bn_data *bn_value_one(void);

/**
 * @brief      : set bn data flags
 * @param[in]  : pa point to struct bn_data
 * @param[in]  : is_secure data secure flags
 */
void bn_set_secure_flags(struct bn_data *pa, u32 is_secure);

/**
 * @brief      : new bn data and copy pa data to new bn data
 */
struct bn_data *bn_dup(const struct bn_data *pa);

/**
 * @brief      : copy pa data to pb bn data
 */
err_bsp_t bn_copy(const struct bn_data *pa, struct bn_data *pb);

/**
 * @brief      : check bn data is odd data is bigend
 * @note       : 1: odd 0:even same to SEC_MEMCHK_ODD
 */
int bn_is_odd(const u8 *pa, u32 size);

/**
 * @brief      : check bn data is valid data is bigend
 * @param[in]  : pa
 * @note       :  1: valid 0: invalid
 */
err_bsp_t bn_is_valid(const struct bn_data *pa);

/**
 * @brief      : data is bigend same to sec_bignum_bitwidth
 * @param[in]  : pa point to struct bn_data
 * @note       : return bitwidth len
 */
u32 bn_get_bitwidth(const struct bn_data *pa);

/**
 * @brief      : bn_get_valid_len unit:byte
 */
u32 bn_get_valid_len(const u8 *pd, u32 size);

/**
 * @brief      : update bn data valid length unit:byte
 */
err_bsp_t bn_update_valid_len(struct bn_data *pbn);

/**
 * @brief      : check bn flag status
 * @param[in]  : pa bignum data
 * @param[in]  : flag from ::enum bn_flags
 */
u32 bn_check_flag(const struct bn_data *pa, enum bn_flags flag);

err_bsp_t bn_bn2bin(const struct bn_data *pfrom, u8 *pto, u32 to_len);

err_bsp_t bn_bin2bn(struct bn_data *pto, const u8 *pfrom, u32 from_len);

err_bsp_t bn_data_check(const struct bn_data *pbn_data);

#endif /* end of __BN_BASIC_H__ */
