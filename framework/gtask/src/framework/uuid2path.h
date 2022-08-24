/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  uuid2path function declaration.
 * Author: yangjing  y00416812
 * Create: 2019-04-18
 */

#ifndef __UUID_TO_PATH_H_
#define __UUID_TO_PATH_H_
#include <tee_defines.h>
#include "gtask_core.h"

int uuid_to_fname(const TEE_UUID *uuid, char *name, int namelen);
int uuid_to_libname(const TEE_UUID *uuid, char *name, int namelen, char *lib_name, tee_img_type_t type);

#endif
