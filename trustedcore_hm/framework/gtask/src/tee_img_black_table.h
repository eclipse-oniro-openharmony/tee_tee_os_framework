/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: test ta load blacklist
 * Create: 2022-02-26
 */

#ifndef TEE_IMG_BLACK_TABLE_H
#define TEE_IMG_BLACK_TABLE_H

#include <tee_defines.h>

bool uuid_is_in_blacklist(const TEE_UUID *uuid);

#endif /* TEE_IMG_BLACK_TABLE_H */
