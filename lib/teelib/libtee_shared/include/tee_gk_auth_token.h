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
