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
#include <sys/hmapi.h>
#include <pathmgr_api.h>

#define PATH_NAME "TEEGlobalTask"

rref_t acquire_gtask_channel(void)
{
    int32_t rc;
    rref_t rref;

    rc = pathmgr_acquire(PATH_NAME, &rref);
    if (rc != 0)
        return ((uint64_t)(((unsigned int)rc) & 0xffffffff));
    return rref;
}
