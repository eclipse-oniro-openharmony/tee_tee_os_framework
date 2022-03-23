/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: sec_flash_public function
 * Author: tjl
 * Create: 2019-08-19
 */
#ifndef _SEC_FLASH_PUBLIC_H_
#define _SEC_FLASH_PUBLIC_H_

#include "tee_defines.h"
#include "tee_inner_uuid.h"

#define WEAK __attribute__((weak))
typedef void (*func_ptr)(void);
/* the num secn flash ipc cmd should begin 0x3100 */
enum SEC_FLASH_IPC_MSG_CMD {
    SEC_FLASH_MSG_FIRST_CMD        = 0x3100,
    SEC_FLASH_MSG_MM_CREATE_CMD,
    SEC_FLASH_MSG_MM_DELETE_CMD,
    SEC_FLASH_MSG_MM_OPEN_CMD,
    SEC_FLASH_MSG_MM_SEEK_CMD,
    SEC_FLASH_MSG_MM_READ_CMD,
    SEC_FLASH_MSG_MM_WRITE_CMD,
    SEC_FLASH_MSG_MM_GET_INFO_CMD,
    SEC_FLASH_MSG_EXT_IS_AVAILABLE_CMD,
    SEC_FLASH_MSG_EXT_FACTORY_RECOVERY_CMD,
    SEC_FLASH_MSG_EXT_POWER_SAVING_CMD,
    SEC_FLASH_MSG_EXT_RESET_CMD,
    SEC_FLASH_MSG_EXT_BINDING_KEY_CMD,
    SEC_FLASH_MSG_EXT_WRITE_LOCK_CMD,
    SEC_FLASH_MSG_LAST_CMD
};

static const TEE_UUID g_sec_flash_uuid = TEE_SERVICE_SEC_FLASH;

#endif
