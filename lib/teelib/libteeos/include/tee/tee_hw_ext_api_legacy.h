/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Create: 2022-04-17
 * Description: Functions in this header file are deprecated. Do not use
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
