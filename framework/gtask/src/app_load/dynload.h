/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  DYNLOAD function declaration.
 * Author: yangjing  y00416812
 * Create: 2019-04-18
 */

#ifndef __DYN_LOAD_H_
#define __DYN_LOAD_H_
#include "ta_framework.h"
#include "gtask_core.h"

typedef struct {
    char *file_buffer;
    int file_size;
    char *lib_name;
    char *fname;
    uint32_t fname_size;
} load_elf_func_params;

#define LIB_EXIST      1
#define LOAD_SUCC      0
#define LOAD_FAIL      (-1)

bool get_dyn_client_name(bool is_64bit,  char *client, uint32_t size);
int dynamic_load_lib_elf(const load_elf_func_params *param, const struct service_struct *service,
                         const TEE_UUID *uuid, uint64_t memid, tee_img_type_t type);
uint32_t sre_release_dynamic_region(const TEE_UUID *uuid, uint32_t release);
#endif
