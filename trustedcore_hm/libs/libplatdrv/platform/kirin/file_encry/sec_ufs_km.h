/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Library for FBE2
 * Author: security-ap
 * Create: 2018-06-11
 */

#ifndef _SEC_UFS_KM_H_
#define _SEC_UFS_KM_H_

#include <stdint.h>

#define IV_LENGTH 64
#define USER_KEY_LENGTH 16
#define UFS_KEY_MAX_NUM 32

#define UFS_KEY_NOT_USED   0x0
#define UFS_KEY_USED       0x5A5A5A5A
/* delete next time */
#define UFS_KEY_TO_DELETE  0xA5A5A5A5

#define FILE_ENCRY_OK                           0
#define FILE_ENCRY_ERROR_INPUT_ERROR            (-1)
#define FILE_ENCRY_ERROR_KEY_IS_FULL            (-2)
#define FILE_ENCRY_ERROR_WRITE_KEY              (-3)
#define FILE_ENCRY_ERROR_NO_THE_KEY             (-4)
#define FILE_ENCRY_ERROR_OUT_OF_MEM             (-5)
#define FILE_ENCRY_ERROR_DER_OUT_OF_MEM         (-6)
#define FILE_ENCRY_ERROR_DER_SETMEM             (-7)
#define FILE_ENCRY_ERROR_DER_MEMCPY_KEY         (-8)
#define FILE_ENCRY_ERROR_DER_MEMORY_UUID        (-9)
#define FILE_ENCRY_ERROR_DERIVE_KEY             (-10)
#define FILE_ENCRY_ERROR_LOCK_FAIL              (-11)
#define FILE_ENCRY_ERROR_GET_MAGIC              (-12)
#define FILE_ENCRY_ERROR_MEMSET_FAIL            (-13)

#define SEC_FILE_ENCRY_CMD_ID_VOLD_ADD_IV       1
#define SEC_FILE_ENCRY_CMD_ID_VOLD_DELETE_IV    2
#define SEC_FILE_ENCRY_CMD_ID_UFS_RESTORE_IV    3

#define FILE_ENCRY_SEM_WAIT_TIME        0xFFFFFFFF

#define FILE_ENCRY_KEY_NORMAL           0x0
#define FILE_ENCRY_KEY_ENHANCED         0x5A

struct ufs_iv {
	uint32_t iv_status;
	uint8_t iv_value[IV_LENGTH];
};

int file_encry_root_derive_key(uint8_t *secret, uint32_t secret_len,
			       uint8_t *key, uint32_t key_len);
int ufs_kirin_uie_key_config(uint32_t key_index, uint8_t *key, uint32_t length);
uint32_t secboot_get_fbe2_flag(uint8_t *fbe2_flag);

#endif
