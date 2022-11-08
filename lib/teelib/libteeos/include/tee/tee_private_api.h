/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef LIBTEEOS_TEE_PRIVATE_API_H
#define LIBTEEOS_TEE_PRIVATE_API_H

#include "tee_defines.h"
#include "tee_crypto_api.h"
#include "tee_hw_ext_api_legacy.h"

TEE_Result tee_ext_get_se_capability(const TEE_UUID *uuid, uint64_t *result);

/*
 * @ingroup TEE_HW_EXT_API
 * @brief   get die id info
 *
 * @param buffer [OUT] buffer to save die id info, buffer length should be checked by get_die_id_size()
 *
 * @retval 0 means success, others means failed
 */
int tee_ext_get_dieid(unsigned int *buffer);

/*
 * @ingroup TEE_HW_EXT_API
 * @brief    check weather device is rooted or not
 *
 * @param NULL
 *
 * @retval 1 means device is rooted, 0 means device not rooted
 */
int tee_is_device_rooted(void);

/*
 * @ingroup TEE_HW_EXT_API
 * @brief convert LSW(Least Significant Word) bytes to MSW(Most Significant Word) bytes
 *
 * @param out_ptr [OUT] convert MSW result
 * @param out_len [IN]  convert MSW result length
 * @param in_ptr  [IN]  data to be converted
 * @param in_len  [IN]  data length to be converted
 *
 * @retval NA
 */
TEE_Result tee_ConvertLswMswWordsToMsbLsbBytes(uint8_t *out_ptr, uint32_t out_len, uint32_t *in_ptr, uint32_t in_len);

/*
 * @ingroup  TEE_HW_EXT_API
 * @brief    get die id length of current chipset
 *
 * @param NULL
 *
 * @retval size of die id
 */
uint32_t get_die_id_size(void);

/*
 * Create anti root timer event
 *
 * @param time_seconds [IN] specified number of seconds
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC create anti root timer fail
 */
TEE_Result TEE_ANTI_ROOT_CreateTimer(uint32_t time_seconds);

/*
 * Destory anti root timer event
 *
 * @return  TEE_SUCCESS success
 * @return  TEE_ERROR_GENERIC destroy anti root timer fail
 */
TEE_Result TEE_ANTI_ROOT_DestoryTimer(void);
#endif
