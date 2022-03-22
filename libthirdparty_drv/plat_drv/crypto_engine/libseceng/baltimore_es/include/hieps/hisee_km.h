/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: km function api
 * Author: l00414685
 * Create: 2019-8-6
 */
#ifndef __HISEE_KM_H__
#define __HISEE_KM_H__
#include <common_km.h>

/**
 * @brief     : Derive a unreadable key from user's input.
 * @param[in] : keytype  : key type, specifies one of the enum symm_ktype.
 * @param[in] : pdin     : pointer the user input.
 * @param[in] : dinlen   : the length of pdin (Byte).
 * @param[o]  : pdoutlen : the length of derived key (Byte).
 * @return    : BSP_RET_OK : succ, other: fail
 */
err_bsp_t hisee_derive_unreadable_key(u32 keytype, const u8 *pdin,
				      u32 dinlen, u32 *doutlen);

/**
 * @brief     : Derive a readable key from user's input.
 * @param[in] : keytype  : key type, specifies one of the enum symm_ktype.
 * @param[in] : pdin     : pointer the user input.
 * @param[in] : dinlen   : the length of pdin (Byte).
 * @param[out]: pdout    : pointer to the buffer for derived keying data.
 * @param[i/o]: pdoutlen : in is outbuffer length, out is key length (Byte).
 * @return    : BSP_RET_OK : succ, other: fail
 */
err_bsp_t hisee_derive_readable_key(u32 keytype, const u8 *pdin,
				    u32 dinlen, u8 *pdout, u32 *doutlen);

#endif /* __HISEE_KM_H__ */

