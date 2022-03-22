/**
 * @file   : api_mac.h
 * @brief  : declare of mac interface
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/20
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_MAC_H__
#define __API_MAC_H__

#include <common_symm.h>
#include <hal_mac.h>

typedef struct api_mac_ctx_struct {
	u32 algorithm;
	u32 mode;
	u8  key[BIT2BYTE(SYMM_WIDTH_256)];
	u32 width;
	u8  iv[SYMM_IVLEN_AES];
	u8  buf[SYMM_BLKLEN_AES];
	u32 blen;
} api_mac_ctx_s;

typedef hal_mac_s api_mac_s;

err_bsp_t api_mac(api_mac_s *pmac_s);

err_bsp_t api_mac_init(api_mac_ctx_s *pctx, u32 algorithm, u32 mode, u8 *pkey, u32 width);

err_bsp_t api_mac_update(api_mac_ctx_s *pctx, pal_master_addr_t pdin, u32 dinlen);

err_bsp_t api_mac_dofinal(api_mac_ctx_s *pctx, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

#endif
