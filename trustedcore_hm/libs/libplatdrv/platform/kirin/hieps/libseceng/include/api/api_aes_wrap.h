/**
 * @file   : api_aes_wrap.h
 * @brief  : declare of api_aes_wrap
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/18
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_AES_WRAP_H__
#define __API_AES_WRAP_H__
#include <common_symm.h>

typedef struct aes_wrap {
	u32        direction;
	u8        *pkey;
	u32        width;
	u8        *pdin;
	u32        dinlen;
	u8        *pdout;
	u32       *pdoutlen;
} api_aes_wrap_s;

err_bsp_t api_aes_wrap(api_aes_wrap_s *pwrap_s);

#endif
