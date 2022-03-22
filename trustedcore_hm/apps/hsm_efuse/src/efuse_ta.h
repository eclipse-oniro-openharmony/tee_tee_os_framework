/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: hsm efuse ta head file
 * Author: huawei
 * Create: 2020-07-10
 */
#ifndef EFUSE_TA_H
#define EFUSE_TA_H

#define HSM_EFUSE_CA                "hsm-ca-efuse-flash"
#define ROOT_UID                    0
#define HWHIAIUSER_UID              1000
#define OPEN_SESSION_PARA_NUM       4
#define HSM_INDEX2_EFUSE            2
#define HSM_INDEX3_EFUSE            3

enum HSM_EFUSE_CMD {
    HSM_SEC_EFUSE_WRITE_CMD = 0x8000,
    HSM_SEC_EFUSE_BURN_CMD = 0x8001,
    HSM_SEC_EFUSE_CHECK_CMD = 0x8002,
};

#endif
