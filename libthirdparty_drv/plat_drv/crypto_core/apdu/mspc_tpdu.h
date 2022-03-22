/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Add the file to support extended command for MSP.
 * Create: 2019-09-09
 */
#ifndef __MSPC_TPDU_H__
#define __MSPC_TPDU_H__
#include <stdint.h>

#define TPDU_RESPONSE_NORMAL            0x5A5AA5A5
#define TPDU_RESPONSE_ABNORMAL          0xA5A55A5A
#define EXT_TPDU_YES_TAG                0x4B4BB4B4
#define EXT_TPDU_NO_TAG                 0xB4B44B4B

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

int32_t mspc_tpdu_receive(uint8_t *rsp_data, uint32_t *rsp_len);
int32_t mspc_extended_apdu_process(uint8_t *cmd_data, uint32_t cmd_len);

#endif

