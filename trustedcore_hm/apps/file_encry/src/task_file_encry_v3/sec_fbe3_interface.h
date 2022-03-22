/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Library for FBE3
 * Create: 2020/01/07
 */

#ifndef __SEC_FBE3_INTERFACE_H_
#define __SEC_FBE3_INTERFACE_H_

#include <stdint.h>
#include "tee_defines.h"
#include "sre_typedef.h"

#define __unused __attribute__((unused))

#define FILE_ENCRY_OK                       0x0
#define FILE_ENCRY_ERROR_CMD_INVALID        0xFBE30001
#define FILE_ENCRY_ERROR_CMD_UNSUPPORT      0xFBE30002
#define FILE_ENCRY_ERROR_CMD_UNDEFINED      0xFBE30003
#define FILE_ENCRY_ERROR_INPUT_FLAG         0xFBE30004
#define FILE_ENCRY_ERROR_INPUT_SLOT         0xFBE30005
#define FILE_ENCRY_ERROR_INPUT_USER         0xFBE30006
#define FILE_ENCRY_ERROR_INPUT_BUFFER       0xFBE30007
#define FILE_ENCRY_ERROR_BUFFER_FROMCA      0xFBE30008
#define FILE_ENCRY_ERROR_LENGTH_FROMCA      0xFBE30009
#define FILE_ENCRY_ERROR_BUFFER_FROMTA      0xFBE3000A
#define FILE_ENCRY_ERROR_LENGTH_FROMTA      0xFBE3000B
#define FILE_ENCRY_ERROR_OUT_OF_MEM         0xFBE3000C
#define FILE_ENCRY_ERROR_MEMSET_FAIL        0xFBE3000D
#define FILE_ENCRY_ERROR_MEMCPY_FAIL        0xFBE3000E
#define FILE_ENCRY_ERROR_INVALID_OPEN       0xFBE3000F
#define FILE_ENCRY_ERROR_INVALID_NEW        0xFBE30010
#define FILE_ENCRY_ERROR_INVALID_LOGOUT     0xFBE30011
#define FILE_ENCRY_ERROR_CKEY_STATUS        0xFBE30012
#define FILE_ENCRY_ERROR_SECE_STATUS        0xFBE30013
#define FILE_ENCRY_ERROR_FILE_TYPE          0xFBE30014
#define FILE_ENCRY_ERROR_CKEY_IS_FULL       0xFBE30015
#define FILE_ENCRY_ERROR_SECE_IS_FULL       0xFBE30016
#define FILE_ENCRY_ERROR_MAGIC_NUM          0xFBE30017
#define FILE_ENCRY_ERROR_IV_VALUE           0xFBE30018
#define FILE_ENCRY_ERROR_NO_SECE_KEY        0xFBE30019
#define FILE_ENCRY_ERROR_SECE_INDEX         0xFBE3001A
#define FILE_ENCRY_ERROR_HASH_VERIFY        0xFBE3001B
#define FILE_ENCRY_ERROR_INPUT_PARAM        0xFBE3001C
#define FILE_ENCRY_ERROR_DELETE_MAINID      0xFBE3001D
#define FILE_ENCRY_ERROR_PUBKEY_LEN         0xFBE3001E
#define FILE_ENCRY_ERROR_RPMB_FILENAME      0xFBE3001F
#define FILE_ENCRY_ERROR_RPMB_COPY_CKEY     0xFBE30020
#define FILE_ENCRY_ERROR_RPMB_FILE_TYPE     0xFBE30021
#define FILE_ENCRY_ERROR_RPMB_VERIFY_MAGIC  0xFBE30022
#define FILE_ENCRY_ERROR_RPMB_VERIFY_BUF    0xFBE30023
#define FILE_ENCRY_ERROR_RPMB_INVALID_PARAM 0xFBE30024
#define FILE_ENCRY_ERROR_RPMB_NOT_SUPPORT   0xFBE30025
#define FILE_ENCRY_ERROR_RPMB_NO_CKEY       0xFBE30026
#define FILE_ENCRY_ERROR_RPMB_ENC_NULL      0xFBE30027
#define FILE_ENCRY_ERROR_RPMB_ENC_NO_IV     0xFBE30028

enum file_type {
	FILE_DE = 0,
	FILE_CE = 1,
	FILE_ECE = 2,
	FILE_SECE = 3,
	FILE_GLOBAL_DE = 4,
	FILE_PRIV = 5,
	FILE_MAX,
};

/* The number of params[] is 4, according to the GPTEE SPEC */
#define PARAM_NUM  4
uint32_t file_encry_prepare_ckey(void);

uint32_t file_encry_restore_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_lock_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_unlock_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_logout_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_add_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_delete_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_new_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_open_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_enable_kdf_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_preload_key(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_msp_status(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
uint32_t file_encry_status_report(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);
/* undefined cmd id */
uint32_t file_encry_undefined(uint32_t paramTypes, TEE_Param params[PARAM_NUM]);

#endif
