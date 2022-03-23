/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hisee tpdu error number list.
 * Create: 2019-11-14
 * History: 2019-11-14 Creat for tpdu MNTN.
 */

#ifndef HISEE_ERR_NO_H
#define HISEE_ERR_NO_H

#define TPDU_FAULT_MODID_OFFSET 24UL
#define tpdu_err_value(mod_id, sub_err)((unsigned int)((\
    (unsigned int)(mod_id) << TPDU_FAULT_MODID_OFFSET) |\
    (0x00FFFFFF & (sub_err))))

enum hisee_tpdu_error_id {
    HISEE_TPDU_ERR = 0x0A,
    HISEE_TPDU_ERR_ID_MAX = 0xFF,
};

enum hisee_tpdu_error_value {
    HISEE_TPDU_CONT_CMD_ERR = 0x01,
    HISEE_TPDU_WAIT_READT_ERR = 0x02,
    HISEE_TPDU_ABNORMAL_RECE_ERR_A = 0x03,
    HISEE_TPDU_ABNORMAL_RECE_ERR_B = 0x04,
    HISEE_TPDU_ABNORMAL_RECE_ERR_C = 0x05,
    HISEE_TPDU_RESP_PROCESS_ERR_A = 0x06,
    HISEE_TPDU_RESP_PROCESS_ERR_B = 0x07,
    HISEE_TPDU_RESP_PROCESS_ERR_C = 0x08,
    HISEE_TPDU_CONT_AND_SEND_ERR_A = 0x09,
    HISEE_TPDU_CONT_AND_SEND_ERR_B = 0x0A,
    HISEE_TPDU_LAST_A = 0x0B,
    HISEE_TPDU_LAST_B = 0x0C,
    HISEE_TPDU_ONE_BLOCK_A = 0x0D,
    HISEE_TPDU_ONE_BLOCK_B = 0x0E,
    HISEE_TPDU_ONE_BLOCK_C = 0x0F,
    HISEE_TPDU_CHECK_PARA_A = 0x10,
    HISEE_TPDU_CHECK_PARA_B = 0x11,
    HISEE_TPDU_EXTEND_PROCESS_ERR_A = 0x12,
    HISEE_TPDU_EXTEND_PROCESS_ERR_B = 0x13,
    HISEE_TPDU_EXTEND_PROCESS_ERR_C = 0x14,
    HISEE_TPDU_EXTEND_PROCESS_ERR_D = 0x15,
    HISEE_TPDU_EXTEND_PROCESS_ERR_E = 0x16,
    HISEE_TPDU_EXTEND_PROCESS_ERR_F = 0x17,
    HISEE_TPDU_EXTEND_PROCESS_ERR_G = 0x18,
    HISEE_TPDU_ERR_VALUE_MAX = 0xFF,
};

#endif /* HISEE_ERR_NO_H */
