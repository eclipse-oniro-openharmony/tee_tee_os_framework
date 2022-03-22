/**
 * @file   : api_hash.h
 * @brief  : declare of hash interface
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/19
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_HASH_H__
#define __API_HASH_H__

#include <hal_hash.h>

typedef hal_hash_ctx_s api_hash_ctx_s;

err_bsp_t api_hash(u32 algorithm, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);

err_bsp_t api_hash_init(api_hash_ctx_s *pctx_s, u32 algorithm);

err_bsp_t api_hash_update(api_hash_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen);

err_bsp_t api_hash_dofinal(api_hash_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen);
#endif
