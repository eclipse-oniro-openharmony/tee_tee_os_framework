/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: handle drv dyn perm info
 * Author: qishuai qishuai6@huawei.com
 * Create: 2021-02-03
 */

#ifndef DYN_CONG_BUILDED_DRV_DYN_CONF_BUILDER_H
#define DYN_CONG_BUILDED_DRV_DYN_CONF_BUILDER_H

#include "dyn_conf_dispatch_inf.h"

struct tag_crew {
    uint32_t item_tag;
    uint32_t data_tag;
    uint32_t type_tag;
    char split_tag;
};

int32_t install_drv_permission(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue);
void uninstall_drv_permission(const void *obj, uint32_t obj_size);
void dump_drv_conf(void);

#endif
