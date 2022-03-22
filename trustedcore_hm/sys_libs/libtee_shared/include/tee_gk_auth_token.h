/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Create: 2021-12-12
 * Description: tee gatekeeper verify timestamp api head file
 */

#ifndef TEE_GK_AUTH_TOKEN_H
#define TEE_GK_AUTH_TOKEN_H

#include "tee_defines.h"

/*
 * Get verify timestamp of this uid from gatekeeper ta. TA can call this API, and this
 * api is only allowed to be invoked by TA.
 *
 * @param uid            [IN]  UID of the verify user.
 * @param timestamp      [IN/OUT]  Auth token timestamp buffer of this verify user.
 *
 * @retval TEE_SUCCESS: success; others: failed
 *
 */
TEE_Result tee_gatekeeper_get_verify_timestamp(uint32_t uid, uint64_t *timestamp);

#endif
