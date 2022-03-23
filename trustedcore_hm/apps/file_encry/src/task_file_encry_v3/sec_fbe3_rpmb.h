/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA for RPMB access headers
 * Create: 2020/06/17
 */

#ifndef __SEC_FBE3_RPMB_H_
#define __SEC_FBE3_RPMB_H_

#include "msp_fbe.h"
#include "sre_typedef.h"

#ifdef FILE_ENCRY_USING_RPMB
uint32_t file_encry_rpmb_read(struct key_info_t *info);
uint32_t file_encry_rpmb_write(const struct key_info_t *info);
uint32_t file_encry_rpmb_delete(const struct key_info_t *info);
uint32_t file_encry_rpmb_ensure_enc(uint32_t user, uint32_t file);
#else
static inline uint32_t file_encry_rpmb_read(struct key_info_t *info __unused) {return 0;}
static inline uint32_t file_encry_rpmb_write(const struct key_info_t *info __unused) {return 0;}
static inline uint32_t file_encry_rpmb_delete(const struct key_info_t *info __unused) {return 0;}
static inline uint32_t file_encry_rpmb_ensure_enc(uint32_t user __unused, uint32_t file __unused)
	{return 0;}
#endif

#endif
