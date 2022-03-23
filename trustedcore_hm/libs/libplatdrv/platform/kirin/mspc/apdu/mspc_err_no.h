/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: mspc tpdu error number list.
 * Create: 2019-11-14
 */

#ifndef MSPC_ERR_NO_H
#define MSPC_ERR_NO_H

#define TPDU_FAULT_MODID_OFFSET     24UL
#define tpdu_err_value(mod_id, sub_err)((unsigned int)((\
    (unsigned int)(mod_id) << TPDU_FAULT_MODID_OFFSET) |\
    (0x00FFFFFF & (sub_err))))

enum mspc_tpdu_error_id {
    MSPC_TPDU_ERR = 0x0A,
    MSPC_TPDU_ERR_ID_MAX = 0xFF,
};

enum mspc_tpdu_error_value {
    MSPC_TPDU_CONT_CMD_ERR = 0x01,
    MSPC_TPDU_WAIT_READT_ERR = 0x02,
    MSPC_TPDU_ABNORMAL_RECE_ERR_A = 0x03,
    MSPC_TPDU_ABNORMAL_RECE_ERR_B = 0x04,
    MSPC_TPDU_ABNORMAL_RECE_ERR_C = 0x05,
    MSPC_TPDU_RESP_PROCESS_ERR_A = 0x06,
    MSPC_TPDU_RESP_PROCESS_ERR_B = 0x07,
    MSPC_TPDU_RESP_PROCESS_ERR_C = 0x08,
    MSPC_TPDU_CONT_AND_SEND_ERR_A = 0x09,
    MSPC_TPDU_CONT_AND_SEND_ERR_B = 0x0A,
    MSPC_TPDU_LAST_A = 0x0B,
    MSPC_TPDU_LAST_B = 0x0C,
    MSPC_TPDU_ONE_BLOCK_A = 0x0D,
    MSPC_TPDU_ONE_BLOCK_B = 0x0E,
    MSPC_TPDU_ONE_BLOCK_C = 0x0F,
    MSPC_TPDU_CHECK_PARA_A = 0x10,
    MSPC_TPDU_CHECK_PARA_B = 0x11,
    MSPC_TPDU_EXTEND_PROCESS_ERR_A = 0x12,
    MSPC_TPDU_EXTEND_PROCESS_ERR_B = 0x13,
    MSPC_TPDU_EXTEND_PROCESS_ERR_C = 0x14,
    MSPC_TPDU_EXTEND_PROCESS_ERR_D = 0x15,
    MSPC_TPDU_EXTEND_PROCESS_ERR_E = 0x16,
    MSPC_TPDU_EXTEND_PROCESS_ERR_F = 0x17,
    MSPC_TPDU_EXTEND_PROCESS_ERR_G = 0x18,
    MSPC_TPDU_ERR_VALUE_MAX = 0xFF,
};

#endif /* MSPC_ERR_NO_H */
