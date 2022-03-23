/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sm2 standard interface
 * Author     : h00401342
 * Create     : 2019/09/03
 * Note       :NA
 */

#ifndef __STANDARD_SM2_BASIC_H__
#define __STANDARD_SM2_BASIC_H__
#include <common_ecc.h>
#include <standard_ecc.h>

/**
 * @brief      : get SM2 p
 * @return     : pointer p
 */
struct bn_data *ecc_get_sm2_pp(void);

/**
 * @brief      : get SM2 A
 * @return     : pointer A
 */
struct bn_data *ecc_get_sm2_pa(void);

/**
 * @brief      : get SM2 B
 * @return     : pointer B
 */
struct bn_data *ecc_get_sm2_pb(void);

/**
 * @brief      : get SM2 N
 * @return     : pointer N
 */
struct bn_data *ecc_get_sm2_pn(void);

/**
 * @brief      : get SM2 Gx
 * @return     : pointer Gx
 */
struct bn_data *ecc_get_sm2_pgx(void);

/**
 * @brief      : get SM2 Gy
 * @return     : pointer Gy
 */
struct bn_data *ecc_get_sm2_pgy(void);

/**
 * @brief      : SM2 init curve para bn struct
 */
void sm2_init_curve_bn(struct ecc_curve_bn *pcurve);

void sm2_init_curve_group(struct ec_curve_group_fp *pcurve);

#endif

