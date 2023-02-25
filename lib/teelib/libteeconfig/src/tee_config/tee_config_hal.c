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
#include "tee_config.h"
#include <string.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include "product_config_hal.h"

int32_t get_tbac_info_by_name(const char *name, uint64_t *sid, uint64_t *job_type)
{
    uint32_t i;
    uint32_t nr = get_drv_frame_nums();
    const struct drv_frame_info *info_list = get_drv_frame_infos();

    if (name == NULL || sid == NULL || job_type == NULL) {
        tloge("bad params\n");
        return -1;
    }

    if (info_list == NULL) {
        tloge("no tbac info\n");
        return -1;
    }

    for (i = 0; i < nr; i++) {
        if (strncmp(name, info_list[i].drv_name, strlen(info_list[i].drv_name) + 1) == 0) {
            *sid = info_list[i].sid;
            *job_type = info_list[i].job_type;
            return 0;
        }
    }
    return -1;
}
