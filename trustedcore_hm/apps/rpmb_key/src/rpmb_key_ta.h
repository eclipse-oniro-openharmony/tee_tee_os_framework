/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rpmb key head file in equipment action
 * Author: chenyao
 * Create: 2020-06-02
 */

#ifndef RPMB_KEY_TA_H
#define RPMB_KEY_TA_H

#ifdef STATIC_SKIP
#define STATIC
#else
#define STATIC static
#endif

#define ROOTSCAN_RPMB               "ufs_rpmb_key"
#define RPMB_KEY_GEN                0x9000
#define RPMB_KEY_TEST               0x9001
#define ROOT_UID                    0
#define HWHIAIUSER_UID              1000
#define RPMB_BAK_WORD_LEN           8
#define RPMB_BAK_SIZE               (sizeof(uint32_t) * RPMB_BAK_WORD_LEN)

#endif
