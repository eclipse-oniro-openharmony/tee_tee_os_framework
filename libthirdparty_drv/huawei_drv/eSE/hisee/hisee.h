/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hisee teeos power driver.
 * Create: 2019/9/30
 */

#ifndef __HISI_HISEE_H__
#define __HISI_HISEE_H__

#define SCARD_CHAIN_TIMEOUT             8000000
#define TEE_GET_APDU                    0xE6
#define HISEE_COPY_DONE                 0xB4
#define NEW_HISEE                       0xC3
#define DONE_FLAG_MASK                  0xFF          /* The low 8 bits record the flag */
#define HISEE_VERSION_MASK              0xFF000000    /* The high 8 bits indicate the hisee version */
#define HISEE_VERSION_OFFSET            24U
#define HISEE_IPC_SEAMPHORE_TIMEOUT     0xFFFFFFFF    /* wait forever */

#define TEE_HISEE_ON                    0xfff0        /* notify BL31, TEE need cos ready and keeping HISEE POWER ON */
#define TEE_HISEE_OFF                   0xfffc        /* notify BL31, HISEE can be shutdown */
#define TEE_HISEE_POWER_ON              0xfff4
#define TEE_HISEE_POWER_OFF             0xfff8
#define TEE_ESE_TRANSMIT                0xfffA
#define TEE_ESE_READ                    0xfffB

#define HISEE_SUCCESS                   0
#define HISEE_FAILURE                   (-1)
#define HISEE_EMPTY                     (-2)

#define HISEE_MIN_VOTE_COUNT            0x0U
#define HISEE_MAX_VOTE_COUNT            0xFU

#define HISEE_DELAY_TIME                10

#ifdef MSP_EXT_TPDU
#define TPDU_RESPONSE_NORMAL            0x5A5AA5A5
#define TPDU_RESPONSE_ABNORMAL          0xA5A55A5A
#define EXT_TPDU_YES_TAG                0x4B4BB4B4
#define EXT_TPDU_NO_TAG                 0xB4B44B4B
#endif

enum se_power_id {
	SE_API_ID  = 0,
	INSE_ENCRYPT_ID,
	MAX_VOTE_ID,
};

enum se_power_status {
	SE_POWER_STATUS_OFF = 0,
	SE_POWER_STATUS_ON  = 0xC3BF5A69,
};

union se_power_vote_status {
	unsigned int value;
	struct {
		unsigned int se_api:4;
		unsigned int inse_encrypt:4;
		unsigned int reserved:24;
	} status;
};

enum se_state {
	SE_STAT_POWER_DOWN        = 0,
	SE_STAT_POWER_UP          = 1,
	SE_STAT_MISC_READY        = 2,
	SE_STAT_COS_READY         = 3,
	SE_STAT_POWER_DOWN_DOING,
	SE_STAT_POWER_UP_DOING,
	SE_STAT_MAX,
};

enum se_pipe_type {
	INSE_ENCRYPTION_PIPE_TYPE = 0x5A,
	SE_API_PIPE_TYPE          = 0xA5,
};

enum se_trans_state {
	TRANS_LAST = 0,
	TRANS_CHAIN,
	TRANS_ABORT,        /* return abort to hisee to abort transmit */
	TRANS_MAX,
};

int hisee_p61_factory_test(void);
int hisee_scard_connect(int reader_id, void *p_atr, unsigned int *atr_len);
int hisee_scard_disconnect(int reader_id);
int hisee_scard_transmit(int reader_id, unsigned char *p_cmd, unsigned int cmd_len,
			 unsigned char *p_rsp, unsigned int *rsp_len);
int hisee_scard_support_mode(void);
#ifdef MSP_EXT_TPDU
int hisee_tpdu_ipc_send(enum se_pipe_type pipe_type, unsigned char *cmd_data, unsigned int cmd_len);
int hisee_tpdu_ipc_receive(enum se_pipe_type pipe_type, unsigned char *rsp_data, unsigned int *rsp_len);
int hisee_tpdu_check_para_and_cos_ready(unsigned char *rsp_data, unsigned int *rsp_len);
#endif

int inse_connect(void *id);
int inse_disconnect(const void *id);

#endif
