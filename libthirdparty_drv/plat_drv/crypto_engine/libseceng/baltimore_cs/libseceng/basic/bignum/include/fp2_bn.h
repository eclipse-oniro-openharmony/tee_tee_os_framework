/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: fp2 bn data process
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */
#ifndef __FP2_BN_H__
#define __FP2_BN_H__
#include <bn_basic.h>

#define FP2_SIZE  2
#define FP2_FIELD 2

typedef struct bn_data *fp2_bn[FP2_SIZE];

err_bsp_t fp2_init(fp2_bn pp);

void fp2_clearup(fp2_bn in);

err_bsp_t fp2_from_bin(fp2_bn pto, const u8 *pfrom, u32 from_len, u32 width);

err_bsp_t fp2_set_pdata(fp2_bn pto, u8 *pfrom, u32 from_len, u32 width);

err_bsp_t fp2_to_bin(const fp2_bn pfrom, u8 *pto, u32 to_len, u32 width);

err_bsp_t fp2_bn_check(const fp2_bn pfp2);

#endif /* end of __FP2_BN_H__ */
