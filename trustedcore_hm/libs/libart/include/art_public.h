/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ART public function
 * Author: c00301810
 * Create: 2020-03-21
 */
#ifndef _ART_PUBLIC_H_
#define _ART_PUBLIC_H_
#include <tee_internal_api.h>

#define WEAK __attribute__((weak))
typedef void (*func_ptr)(void);
/* art ipc cmd should begin 0x8100 */
enum ART_IPC_MSG_CMD {
    ART_MSG_ALLOC_CMD = 0x8100,
    ART_MSG_READ_CMD,
    ART_MSG_INCREASE_CMD,
    SAMGR_MSG_EXT_LOAD_CMD,
    SAMGR_MSG_EXT_INSTALL_CMD,
    SAMGR_MSG_EXT_GETSTATUS_CMD
};

#endif
