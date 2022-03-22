/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA for FBE3
 * Create: 2020/01/09
 */

#ifndef __SEC_FBE3_TA_H_
#define __SEC_FBE3_TA_H_

#include "sec_fbe3_interface.h"
#include "sre_typedef.h"

#define __default __attribute__((visibility("default")))

#define SEC_FE_UFS_NAME     "ufs_key_restore"
#define SEC_FE_UFS_UID      0

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
enum FILE_ENCRY_CMD_ID {
	SEC_FILE_ENCRY_CMD_ID_VOLD_ADD_IV = 0x1,
	SEC_FILE_ENCRY_CMD_ID_VOLD_DELETE_IV = 0x2,
	SEC_FILE_ENCRY_CMD_ID_LOCK_SCREEN = 0x3,
	SEC_FILE_ENCRY_CMD_ID_UNLOCK_SCREEN = 0x4,
	SEC_FILE_ENCRY_CMD_ID_KEY_RESTORE = 0x5,
	SEC_FILE_ENCRY_CMD_ID_NEW_SECE = 0x6,
	SEC_FILE_ENCRY_CMD_ID_GEN_METADATA = 0x7,
	SEC_FILE_ENCRY_CMD_ID_USER_LOGOUT = 0x8,
	SEC_FILE_ENCRY_CMD_ID_ENABLE_KDF = 0x9,
	SEC_FILE_ENCRY_CMD_ID_PRELOADING = 0xA,
	SEC_FILE_ENCRY_CMD_ID_MSP_STATUS = 0xB,
	SEC_FILE_ENCRY_CMD_ID_STATUS_REPORT = 0xC,
	/* Reserve cmd id 0xC - 0xF for future using */
	SEC_FILE_ENCRY_CMD_ID_INVALID = 0x10,
};

#define SEC_FILE_ENCRY_CMD_ID_MASK           0xF

#define CALLBACK_FN(num, name) [num] = file_encry_##name,

typedef uint32_t (*file_encry_cb)(uint32_t paramTypes, TEE_Param params[4]);

#define FILE_ENCRY_LIST \
	CALLBACK_FN(0x00, undefined) \
	CALLBACK_FN(0x01, add_interface) \
	CALLBACK_FN(0x02, delete_interface) \
	CALLBACK_FN(0x03, lock_interface) \
	CALLBACK_FN(0x04, unlock_interface) \
	CALLBACK_FN(0x05, restore_interface) \
	CALLBACK_FN(0x06, new_interface) \
	CALLBACK_FN(0x07, open_interface) \
	CALLBACK_FN(0x08, logout_interface) \
	CALLBACK_FN(0x09, enable_kdf_interface) \
	CALLBACK_FN(0x0A, preload_key) \
	CALLBACK_FN(0x0B, msp_status) \
	CALLBACK_FN(0x0C, status_report) \
	CALLBACK_FN(0x0D, undefined) \
	CALLBACK_FN(0x0E, undefined) \
	CALLBACK_FN(0x0F, undefined)
#endif
