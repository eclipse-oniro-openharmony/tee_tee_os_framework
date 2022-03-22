/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TEE TA FBE3 -> MSP SA FBE communication API.
 * Create: 2020-01-20
 */

#ifndef MSP_FBE_H
#define MSP_FBE_H

#include "sec_fbe3_interface.h"
#include "tee_internal_api.h"
#include "tee_ext_api.h"

#define MSP_SUCCESS 0

#ifdef DEF_ENG
#define MSP_DEBUG_P
#endif /* DEF_ENG */

struct key_info_t {
	uint32_t user_id;
	uint32_t file_type;
	uint8_t *magic_buf;
	uint32_t magic_len;
	uint8_t *key_buf;
	uint32_t key_len;
};

#ifdef MSP_DEBUG_P
uint32_t msp_fbe_inquiry_key(void);
uint32_t msp_fbe_reset_key(void);
#endif /* MSP_DEBUG_P */

#ifdef FILE_ENCRY_MSP_ENABLE
uint32_t msp_fbe_try(uint32_t *version);
uint32_t msp_fbe_prefetch_key(uint32_t user_id);
uint32_t msp_fbe_fetch_key(struct key_info_t *info);
uint32_t msp_fbe_fetch_key_enhance(struct key_info_t *info);
uint32_t msp_fbe_delete_key(struct key_info_t *info);
#else
static inline uint32_t msp_fbe_try(uint32_t *version __unused) {return 0; }
static inline uint32_t msp_fbe_prefetch_key(uint32_t user_id __unused) {return 0; }
static inline uint32_t msp_fbe_fetch_key(struct key_info_t *info __unused) {return 0; }
static inline uint32_t msp_fbe_fetch_key_enhance(struct key_info_t *info __unused) {return 0; }
static inline uint32_t msp_fbe_delete_key(struct key_info_t *info __unused) {return 0; }
#endif
#endif
