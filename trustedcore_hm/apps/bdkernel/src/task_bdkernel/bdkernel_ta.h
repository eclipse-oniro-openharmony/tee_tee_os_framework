/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: This file contains the function required for TEE
 * Author: Xu Hangyu x00447026
 * Create: 2018-08-30
 */
#ifndef BDKERNEL_TA_H
#define BDKERNEL_TA_H

#include "securec.h"

#define BDKERNEL_CA_PACKAGE_NAME "/dev/bdkernel_ca"
#define ROOT_UID 0

#define APP_PROCESS32_NAME "/system/bin/app_process32"
#define APP_PROCESS64_NAME "/system/bin/app_process64"
#define SYSTEM_SERVER_NAME "system_server"
#define SYSTEM_UID 1000

enum HWAATaCmd {
    CMD_HWAA_INIT_USER = 10,
};
#endif
