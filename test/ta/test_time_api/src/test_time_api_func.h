/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef __TEST_TIME_API_FUNC_H__
#define __TEST_TIME_API_FUNC_H__

#include <tee_ext_api.h>

#define MILLISECOND 1000
#define PERSISTENT_TIME_BASE_FILE "sec_storage/persistent_time"

enum TEST_TIME_API_CMD_ID {
    CMD_ID_TEST_GET_SYSTEM_TIME = 0,
    CMD_ID_TEST_TEE_WAIT = 1,
    CMD_ID_TEST_GET_PERSISTENT_TIME = 2,
    CMD_ID_TEST_SET_PERSISTENT_TIME = 3,
    CMD_ID_TEST_GET_REE_TIME = 4,
};

TEE_Result TestTimeApi(uint32_t cmdId, TEE_Param params[4]);
#endif