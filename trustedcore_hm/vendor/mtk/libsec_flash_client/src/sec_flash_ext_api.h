/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sec_flash_ext_api function
 * Author: lvtaolong
 * Create: 2019-10-15
 */
#ifndef SEC_FLASH_EXT_API_H
#define SEC_FLASH_EXT_API_H

#include <stdint.h>
#include "tee_defines.h"

#define SF_BINDING_KEY_LEN_IN_BYTES  48
/* For Baltimore, we just use SECFLASH_IS_EXIST_MAGIC and SECFLASH_IS_ABSENCE_MAGIC */
#define SECFLASH_IS_ABSENCE_MAGIC    0x70eb2c2d
#define SECFLASH_IS_EXIST_MAGIC      ~SECFLASH_IS_ABSENCE_MAGIC
#define SECFLASH_NXP_EXIST_MAGIC     0xa5c89cea
#define SECFLASH_ST_EXIST_MAGIC      0xe59a6b89

#define SECFLASH_RESET_TYPE_SOFT 0
#define SECFLASH_RESET_TYPE_HARD 1

TEE_Result TEE_EXT_SecFlashIsAvailable(uint32_t *status_info);
TEE_Result TEE_EXT_SecFlashFactoryRecovery(uint32_t flags);
TEE_Result TEE_EXT_SecFlashPowerSaving(void);
TEE_Result TEE_EXT_SecFlashReset(uint32_t reset_type);
TEE_Result TEE_EXT_SecFlashGetBindingKey(uint8_t *key_buf, uint32_t buf_len);
TEE_Result TEE_EXT_SecFlashWriteLockEnable(bool is_set_operation);
TEE_Result TEE_EXT_MspcRecovery(uint32_t flags);
TEE_Result TEE_EXT_MspcPowerOn(uint32_t vote_id);
TEE_Result TEE_EXT_MspcPowerOff(uint32_t vote_id);
TEE_Result TEE_EXT_MSPIsAvailable(uint32_t *status);
#endif
