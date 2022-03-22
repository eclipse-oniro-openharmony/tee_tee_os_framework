/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description:fp4 bn data process
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/02/26
 */
#ifndef __FP4_BN_H__
#define __FP4_BN_H__
#include <fp2_bn.h>

#define FP4_SIZE   2
#define FP4_FIELD  4

typedef fp2_bn fp4_bn[FP4_SIZE];

err_bsp_t fp4_init(fp4_bn pp);

void fp4_clearup(fp4_bn in);

err_bsp_t fp4_bn_check(const fp4_bn pfp4);

err_bsp_t fp4_from_bin(fp4_bn pto, const u8 *pfrom, u32 from_len, u32 width);

/**
 * @brief      : set pfrom point to bn pdata
 */
err_bsp_t fp4_set_pdata(fp4_bn pto, u8 *pfrom, u32 from_len, u32 width);

err_bsp_t fp4_to_bin(const fp4_bn pfrom, u8 *pto, u32 to_len, u32 width);

#endif /* end of __FP4_BN_H__ */
