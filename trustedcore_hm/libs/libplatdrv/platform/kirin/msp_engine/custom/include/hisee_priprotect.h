/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: privacy protection special function interface
 * Author: h00401342, hanyan7@huawei.com
 * Create: 2020/03/09
 */

#ifndef __HISEE_PRIPROTECT_H__
#define __HISEE_PRIPROTECT_H__
#include <common_define.h>

/**
 * @brief      : private protect key derive base kdr
 * @param[in]  : pdin derive weight
 * @param[in]  : dinlen derive weight length
 * @param[in]  : pdout derive key
 * @param[in/out]  : pdoutlen derive key length
 * @note       :
 */
err_bsp_t hisee_pri_protect_derive_kdr(const u8 *pdin, u32 dinlen,
				       u8 *pdout, u32 *pdoutlen);

#endif /* end of __HISEE_PRIPROTECT_H__ */
