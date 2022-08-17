/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * Description: Declare the product interface that teeos depends on
 * Create: 2022-04-12
 */
#include <stdint.h>
#include <stddef.h>

#define WEAK __attribute__((weak))

WEAK const struct dynamic_mem_uuid_item *get_dyn_mem_config(void)
{
    return NULL;
}

WEAK uint32_t get_dyn_mem_config_num(void)
{
    return 0;
}

WEAK const struct drvlib_load_caller_info *get_drvlib_load_caller_infos(void)
{
    return NULL;
}

WEAK uint32_t get_drvlib_load_caller_nums(void)
{
    return 0;
}

WEAK const struct task_info_st *get_product_builtin_task_infos(void)
{
    return NULL;
}

WEAK uint32_t get_product_builtin_task_num(void)
{
    return 0;
}

WEAK const struct rsv_mem_pool_uuid_item *get_rsv_mem_pool_config(void)
{
    return NULL;
}

WEAK uint32_t get_rsv_mem_pool_config_num(void)
{
    return 0;
}

WEAK uint32_t get_product_service_property_num(void)
{
    return 0;
}

WEAK const struct ta_property *get_product_service_property_config(void)
{
    return NULL;
}

WEAK uint32_t get_product_dynamic_ta_num(void)
{
    return 0;
}

WEAK const struct ta_permission *get_product_ta_permission_config(void)
{
    return NULL;
}
