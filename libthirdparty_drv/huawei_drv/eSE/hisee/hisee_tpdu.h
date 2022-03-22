/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Add the file to support extended command for MSP.
 * Create: 2019-09-09
 * History: 2019-09-09 Creat the file.
 */
#ifndef HISEE_TPDU_H
#define HISEE_TPDU_H
#include "hisee.h"

/* Some macros for exended apdu envelope */
#define MAX_NORMAL_COMMAND_LENGTH                       0x0106
#define MAX_EXT_COMMAND_LENGTH                          0x7FF7
#define MAX_BLOCK_SIZE_OF_EXTENDED_APDU                 0x1000
#define CMD_CLA_OFFSET                                  0x00
#define ENVELOPE_HEAD_LENGTH                            0x07
#define ENVELOPE_CLA_OFFSET                             0x00
#define ENVELOPE_INS_OFFSET                             0x01
#define ENVELOPE_INS                                    0xc2
#define ENVELOPE_P1_OFFSET                              0x02
#define ENVELOPE_P1_STATE_MORE                          0x00
#define ENVELOPE_P1_STATE_LAST                          0x80
#define ENVELOPE_P2_OFFSET                              0x03
#define ENVELOPE_C5_OFFSET                              0x04
#define ENVELOPE_C6_OFFSET                              0x05
#define ENVELOPE_C7_OFFSET                              0x06
#define ENVELOPE_CDATA_OFFSET                           0x07
#define ENVELOPE_MAX_CDATA_SIZE                         0xFF9
#define ENVELOPE_RESPONSE_LENGTH                        0x02
#define ENVELOPE_RECEIVE_TIMEOUT                        1000
#define BIT_COUNT_PER_BYTE                              8
#define EVERY_LOOP_DELAY_TIME                           10
#define TPDU_PROCESS_LOCK_IN                            1

unsigned int hisee_tpdu_get_response_status(void);
unsigned int hisee_tpdu_get_ext_tag(void);
void hisee_tpdu_set_ext_tag(unsigned int tag);
int hisee_tpdu_abnormal_receive_data(unsigned char *rsp_data,
                                     unsigned int *rsp_len);
int hisee_extended_apdu_process(enum se_pipe_type pipe_type,
                                unsigned char *cmd_data,
                                unsigned int cmd_len);

#endif

