/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: standard sce interface
 * Author: l00414685
 * Create: 2019-8-6
 */

#ifndef __STANDARD_SCE_H__
#define __STANDARD_SCE_H__
#include <common_sce.h>

u32 symm_get_blklen(u32 alg);
u32 symm_get_ivlen(u32 alg);
u32 symm_get_doutlen(u32 alg, u32 mode, u32 dinlen);
const u8 *symm_get_hash_init_iv(u32 alg);

#endif /* end of __STANDARD_SCE_H__ */
