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

#ifndef __TEE_HW_EXT_API_LEGACY_H__
#define __TEE_HW_EXT_API_LEGACY_H__

#include "tee_defines.h"

TEE_Result TEE_EXT_GetSeCapability(const TEE_UUID *uuid, uint64_t *result);

#ifndef CONFIG_OH_PLATFORM
struct ta_caller_info;


/*
 * Get caller info of current session, refer caller_info struct for more details
 *
 * @param caller_info_data [OUT] caller info to be returned
 * @param length           [IN] sizeof struct caller_info
 *
 * return TEE_SUCCESS operation success
 * return others failed to get caller info
 */
TEE_Result TEE_EXT_GetCallerInfo(struct ta_caller_info *caller_info_data, uint32_t length);

/*
 * get cruurent session type
 *
 * @return session type of current session
 */
uint32_t TEE_GetSessionType(void);
#endif
#endif
