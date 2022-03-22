/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: the antiroot_task.h for TEE antiroot using
 * Create: 2018-05-21
 */

#ifndef _ANTIROOT_TASK_H_
#define _ANTIROOT_TASK_H_

#include "tee_defines.h"

#define CMD_GET_LOCK_TEE_STATE 0x4

#define KEY_LENGTH             32 /* aes256 */
#define DATA_HASH_SIZE         32

typedef struct {
	uint8_t data[DATA_HASH_SIZE];
} hash_t; /* SHA-256 */

#define COUNTER_LENGTH         KEY_LENGTH
#define MAX_CHALLENGE_LENGTH   16
#define SYSTEM_UID             1000

#define ANTIROOT_DB            0
#define ANTIROOT_ENCRYPTO      0
#define ANTIROOT_DECRYPTO      1

#define MAX_PROCSLEN           3680
#define ANTIROOT_IV_LEN        16
/* 320 is reserved for sizeof(struct RAGENT_COMMAND) */
#define ANTIROOT_SRC_LEN       (320 + MAX_PROCSLEN)
#define ANTIROOT_DST_LEN       (ANTIROOT_IV_LEN + ANTIROOT_SRC_LEN)
#define SIZE_CMD_BUFF          4096

#define MAGIC "HWRS"
#define ANTIROOT_RAND_MAX      0xFFFF
#define ENG_VERSION            0
#define TEE_MAX_PARAM_NUM      4
#define MAX_ERROR_TIME         3

/* ERROR from TEE API */
#define AR_ERR_SYS_ERROR       TEE_ERROR_GENERIC

/* ERROR from TEE_Malloc */
#define AR_ERR_OUT_OF_MEM      TEE_ERROR_OUT_OF_MEMORY

/* ERROR from response info check fail */
#define AR_ERR_RSP_CHECK_FAIL  TEE_ERROR_ANTIROOT_RSP_FAIL

/* return value to CA */
#define REV_NOT_ROOT           0x0
#define REV_ROOTED             AR_ERR_RSP_CHECK_FAIL

/*
 * ERROR from processing invokecmd, like:
 *	g_invoke_cmd_state error
 *	error during process cmd
 */
#define AR_ERR_INVOKE_ERROR    TEE_ERROR_ANTIROOT_INVOKE_ERROR

/* config for measuring kernel in tee */
#define TEE_KERNEL_MEASUREMENT

#define TEE_RODATA_MEASUREMENT

#define __UNUSED__ __attribute__((__unused__))

/*
 * the offset of buffer which receive physical address from CA,
 * such as start or end address of kcode
 */
#define OFFSET_KCODE_ADDR_START    0
#define OFFSET_KCODE_ADDR_END      1
#define OFFSET_SYSCALL_ADDR_START  2
#define OFFSET_SYSCALL_NUM         3
#define OFFSET_SEHOOKS_NUM         4
#define OFFSET_SEHOOKS_ADDR_START  5

#ifdef TEE_RODATA_MEASUREMENT
#define OFFSET_RODATA_ADDR_START   (OFFSET_SEHOOKS_ADDR_START + g_se_hooks_num)
#define OFFSET_RODATA_ADDR_END     (OFFSET_RODATA_ADDR_START + 1)
#endif

typedef enum {
	KERNELCODE = 0,
	SYSTEMCALL,
	ROOTPROC,
	SESTATUS,
	SEHOOK,
	SETID,
	RODATA,
	SEPOLICY,
	PROCINTER,
	FRAMINTER,
	INAPPINTER,
	CPUUTIL,
	POWER,
	ISCHARGE,
	CURRENTTIME,
	NOOP,
	TOTALNUM
} chagellenge_id;

/* !DO KEEP "root_status_bit" sync with "sre_rwroot.h" */
typedef enum {
	ROOTSTATE_BIT   = 0,    /* 0    on */
	/* read from fastboot */
	OEMINFO_BIT,            /* 1    on */
	FBLOCK_YELLOW_BIT,      /* 2    on */
	FBLOCK_RED_BIT,         /* 3    on */
	FBLOCK_ORANGE_BIT,      /* 4    on */
	/* dy scan result */
	KERNELCODEBIT   = 6,    /* 6    on */
	SYSTEMCALLBIT,          /* 7    on */
	ROOTPROCBIT,            /* 8    on */
	SESTATUSBIT,            /* 9    on */
	SEHOOKBIT       = 10,   /* 10   on */
	SEPOLICYBIT,            /* 11   off */
	PROCINTERBIT,           /* 12   off */
	FRAMINTERBIT,           /* 13   off */
	INAPPINTERBIT,          /* 14   off */
	NOOPBIT        = 15,    /* 15   on */
	ITIMEOUTBIT,            /* 16   on */
	EIMABIT,                /* 17   on */
	SETIDBIT,               /* 18   on */
	CHECKFAILBIT,           /* 19   on */
	RODATABIT,              /* 20   on */
	TOTALBIT
} root_status_bit;

typedef enum {
	ANTIROOT_CA_ACCESS = 0x1,
	ANTIROOT_TA_ACCESS = 0x2,
	ANTIROOT_BAD_ACCESS = 0xffffffff,
} antiroot_access;

typedef enum {
	STATE_INIT = 0,
	STATE_WHITELIST,
	STATE_CHALLENGE,
} invoke_cmd_state_t;

typedef enum {
	CMD_SET_WHITELIST = 0x1,
	CMD_SEND_CHALLENGE,
	CMD_GET_RESPONSE,
	CMD_EIMA_CHALLENGE,
	CMD_EIMA_RESPONSE,

#ifdef TEE_KERNEL_MEASUREMENT
	CMD_GET_REE_KERNEL_PHYSICAL_ADDR = 0x06,
	CMD_PAUSE_MEASURE,
	CMD_RESUME_MEASURE,

#ifdef DEF_ENG
	CMD_TEE_STATUS_TEST,
#endif
#endif

	CMD_GET_DEVICE_ROOT_STATUS = 0x1000, /* get root status from tee */
	CMD_GET_DEVICE_ROOT_STATUS_DETAIL = 0x1001 /* get root status details from tee */
} eima_cmd_id;

typedef struct {
	int opid;
	int enabled;

	/*
	 * The maximal period to challenge this operation.
	 * If the power/time/cpu info is compromized, we should guarantee
	 * to challenge this operation once every [max_period] requests.
	 */
	int max_period;
	/*
	 * The frequency to challenge this operation when the phone
	 * is idle & charging.
	 * For example, if idle_freq=2, then there is 50% chance we challenge
	 * it when the phone is idle & charging.
	 * idle_period should not be larger than max_period.
	 */
	int idle_period;
	/*
	 * Each check item corresponds to a bit in the final check result about
	 * root status. A mapping is established here to check the status of
	 * the final check result based on the check item.
	 */
	uint32_t root_status_bit;
} operation_config;

typedef struct {
	uint32_t d_status;
	/* for decrypt the  challenge requests */
	unsigned char cha_req_key[KEY_LENGTH];
	/* for encrypto the challenge feedback */
	unsigned char cha_key[KEY_LENGTH];
	hash_t kernel_hash;
	hash_t sys_call_hash;
	hash_t se_hooks_hash;
	hash_t ro_data_hash;
	uint32_t  se_linux_switch;
	uint32_t  procs_len;
	uint32_t  setid;
	unsigned char *root_procs;
} whitelist;

typedef struct {
	/* 32 byte aes key cipher challenge request  */
	uint8_t cha_req_key[KEY_LENGTH];
	/* 32 byte aes key cipher challenge  */
	uint8_t cha_key[KEY_LENGTH];
} tee_rm_cipher_key;

typedef struct {
	uint32_t d_status;
	hash_t   kcode;
	hash_t   syscalls;
	uint32_t selinux;
	hash_t   sehooks;
	uint32_t procs_len;
	uint32_t setid;
	hash_t rodata;
} tee_rm_white_list;

typedef struct {
	tee_rm_cipher_key cipher_key;                      /* cipher key */
	tee_rm_white_list white_list;                      /* white listi */
} tee_rm_config;

typedef struct {
	uint32_t cpu;
	uint32_t power;
	uint32_t charger;
	uint32_t time;
	uint32_t timezone;
	uint8_t  nounce[COUNTER_LENGTH]; /* nounce as key for responce  */
	uint32_t challengeid[MAX_CHALLENGE_LENGTH];
} tee_rm_challenge;

typedef struct {
	tee_rm_white_list white_list;  /* white information in runtime */
	uint32_t proc_integrated;
	uint32_t noop;
} tee_rm_response;

typedef struct {
	uint8_t nounce[COUNTER_LENGTH]; /* nounce as key for responce  */
} tee_eima_challenge;

typedef struct {
	uint8_t msg_type;
} tee_eima_response;

typedef union {
	tee_rm_config config;
	tee_rm_challenge challenge;
	tee_rm_response response;
	tee_eima_challenge eima_challenge;
	tee_eima_response eima_response;
} tee_rm_content;

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint32_t interface;
	tee_rm_content content;
	char buf[1];        /* Data points here, 1 for pclint */
} tee_rm_command;

TEE_Result antiroot_open_session(void);
TEE_Result antiroot_hand_cmd(TEE_Param params[TEE_MAX_PARAM_NUM],
			uint32_t cmd_id);
void antiroot_close_session(void);
uint32_t get_eng_status(void);
uint32_t antiroot_get_root_status(void);
uint32_t antiroot_get_root_status_detail(void);
#endif
