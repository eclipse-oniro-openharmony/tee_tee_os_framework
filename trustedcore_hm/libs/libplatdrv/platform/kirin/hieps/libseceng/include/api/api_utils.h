/**
 * @file   : api_utils.h
 * @brief  : declare of utils
 * @par    : Copyright (c) 2018-2018, HUAWEI Technology Co., Ltd.
 * @date   : 2018/12/18
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __API_UTILS_H__
#define __API_UTILS_H__
#include <common_symm.h>

#define MAX_DATA_SUPPORT 0xF000

#define CRT_PRIVKEY_LEN(width)  (BIT2BYTE(width) >> 1)

typedef struct struct_kdf {
	const u8        *pz;           /* pointer to z */
	u32              zlen;         /* byte length of pz */
	u32              algorithm;    /* hash algorithm */
	const u8        *potherinfo;   /* pointer to other info, cant be NULL */
	u32              otherinfolen; /* byte length of other info */
	u8              *pkey;         /* pointer to outbuffer which holds out key */
	u32              keylen;       /* byte length of key */
} api_kdf_s;

err_bsp_t api_kdf(api_kdf_s *pkdf_s);

#endif
