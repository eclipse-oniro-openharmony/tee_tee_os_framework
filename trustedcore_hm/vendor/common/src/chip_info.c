/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Description: functions to get chip info
 * Create: 2020-4-6
 */
#include "chip_info.h"

/*
 * This function is used to skip the "input module has no datalayout" compilation error,
 * when llvm12 is used in the CMake compilation framework.
 */
int chip_info_skip_compiler_no_datalayout_error()
{
    return 0;
}