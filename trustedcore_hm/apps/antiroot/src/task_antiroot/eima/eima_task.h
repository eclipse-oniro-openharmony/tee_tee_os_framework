/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: the eima_task.h for TEE antiroot using
 * Create: 2018-06-11
 */

#ifndef _EIMA_TASK_H_
#define _EIMA_TASK_H_

#include "tee_internal_api.h"

#define FNAME_LENGTH  256
#define UNAME_LENGTH  20
#define TARGET_NUM    20
#define USECASE_NUM   3
#define HASH_LENGTH   32 /* sha256 */
#define KEY_LENGTH    32 /* aes256 */
#define EIMA_DB       0
#define EIMA_ENCRYPTO 0
#define EIMA_DECRYPTO 1
#define EIMA_STATE_CHALLENGE 0
#define EIMA_STATE_RESPONSE  1
/* 320 is reserved for sizeof(struct RAGENT_COMMAND) */
#define EIMA_SRC_LEN    (320 + MAX_PROCSLEN)
#define EIMA_DST_LEN    (EIMA_IV_LEN + EIMA_SRC_LEN)
#define EIMA_IV_LEN     16
#define EIMA_RAND_MAX   0xFFFF

#ifndef TEE_MAX_PARAM_NUM
#define TEE_MAX_PARAM_NUM 4
#endif

typedef struct {
	uint8_t type;
	uint8_t hash_len;
	uint8_t hash[HASH_LENGTH];
	uint16_t fname_len;
	char *fname;
} eima_integrity_target;

typedef struct {
	uint8_t usecase_name[UNAME_LENGTH];
	uint32_t target_count;
	eima_integrity_target target[TARGET_NUM];
} eima_policy;

typedef struct {
	uint32_t policy_count;
	eima_policy usecase_policy[USECASE_NUM];
} eima_whitelist;

typedef enum {
	EIMA_MSG_WHITELIST = 0,
	EIMA_MSG_BASELINE,
	EIMA_MSG_RUNTIME_INFO,
} eima_rsp_msg;

#ifndef UINT16_MAX
#define UINT16_MAX (uint16_t)(~0U)
#endif

struct sbuf_iter {
	const void *buf;
	const unsigned int size;
	uint16_t index;
};

#ifdef DEBUG_DUMP_HEX
typedef enum {
	EIMA_DUMP_IDX_0 = 0,
	EIMA_DUMP_IDX_1,
	EIMA_DUMP_IDX_2,
	EIMA_DUMP_IDX_3,
	EIMA_DUMP_IDX_4,
	EIMA_DUMP_IDX_5,
	EIMA_DUMP_IDX_6,
	EIMA_DUMP_IDX_7,
	EIMA_DUMP_IDX_8,
	EIMA_DUMP_IDX_9,
	EIMA_DUMP_IDX_10,
	EIMA_DUMP_IDX_11,
	EIMA_DUMP_IDX_12,
	EIMA_DUMP_IDX_13,
	EIMA_DUMP_IDX_14,
	EIMA_DUMP_IDX_15,
	EIMA_DUMP_IDX_MAX,
};
#endif

#define EIMA_SHA256_SIZE 32
#define EIMA_MIN_HASH_SIZE EIMA_SHA256_SIZE
#define EIMA_MAX_HASH_SIZE 64
#define EIMA_HASH_SIZE IMA_SHA256_SIZE
/* Includes null byte */
#define EIMA_MIN_FILENAME_SIZE 2
/* Should match Linux kernel PATH_MAX (uapi/linux/limits.h) */
#define EIMA_MAX_FILENAME_SIZE 4096
#define IMA_DESERIALIZATION_MIN_SIZE 10

/* ERROR NUMBER */
#define EIMA_OK 0                                     /* success */
#define EIMA_DESERIALIZATION_FILENAME_NO_NULL_END 245 /* filename not \0 end */
#define EIMA_DESERIALIZATION_FILENAME_SIZE 246        /* filename size error */
#define EIMA_DESERIALIZATION_FILENAME_NULL 247        /* filename is empty */
#define EIMA_NO_MEM 248                               /* memory is empty */
#define EIMA_DESERIALIZATION_HASH_SIZE 249            /* hash size error */
#define EIMA_DESERIALIZATION_SIZE_FAILURE 250         /* size error */
#define EIMA_DESERIALIZATION_EMPTY_LIST_FAILURE 251   /* linked list empty */
#define EIMA_INTEGRITY_LIST_EMPTY 252                 /* trust list empty */
#define EIMA_POLICY_EXISTS 253                        /* policy exists */
#define EIMA_MEASUREMENT_NOT_FOUND 254                /* measure not found */
#define EIMA_WRONG_HASH 255                           /* hash value wrong */

void eima_deinit(void);
TEE_Result eima_handle_cmd(TEE_Param params[TEE_MAX_PARAM_NUM],
			uint32_t cmd_id);
TEE_Result eima_init(void);
#endif
