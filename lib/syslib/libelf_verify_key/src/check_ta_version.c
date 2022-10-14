/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: root cert info for checking TA image validation
 * Create: 2021-02-28
 */

#include "check_ta_version.h"

bool ta_local_sign_check(void)
{
#ifdef TA_LOCAL_SIGN
    return true;
#endif
    return false;
}

bool is_keywest_signature(void)
{
#ifdef KEYWEST_SIGN_PUB_KEY
    return true;
#endif
    return false;
}

