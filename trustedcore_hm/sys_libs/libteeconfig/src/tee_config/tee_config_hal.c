/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: functions to get configs
 * Create: 2020-03-10
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

/* next 3 functions for permission config */
uint32_t get_dynamic_ta_num(void)
{
    return get_teeos_ta_permission_num() + get_product_dynamic_ta_num();
}

const struct ta_permission *get_permission_config_by_index(uint32_t num)
{
    uint32_t teeos_ta_num = get_teeos_ta_permission_num();
    const struct ta_permission *teeos_config = NULL;
    uint32_t product_ta_num = get_product_dynamic_ta_num();
    const struct ta_permission *product_config = NULL;

    if (num >= (teeos_ta_num + product_ta_num))
        return NULL;

    if (num < teeos_ta_num) {
        teeos_config = get_teeos_ta_permission_config();
        if (teeos_config == NULL)
            return NULL;
        return &(teeos_config[num]);
    }
    product_config = get_product_ta_permission_config();
    if (product_config == NULL)
        return NULL;
    return &product_config[num - teeos_ta_num];
}

/* each dependent driver has a white table for uuid-libname */
bool is_modload_perm_valid(const TEE_UUID *uuid, const char *name)
{
    uint32_t item_num = get_drvlib_load_caller_nums();
    const struct drvlib_load_caller_info *info_list = get_drvlib_load_caller_infos();

    if (uuid == NULL || name == NULL || info_list == NULL)
        return false;

    for (uint32_t i = 0; i < item_num; i++) {
        if (memcmp(&info_list[i].uuid, uuid, sizeof(*uuid)) == 0 &&
            strncmp(info_list[i].name, name, strlen(info_list[i].name) + 1) == 0)
            return true;
    }

    return false;
}
