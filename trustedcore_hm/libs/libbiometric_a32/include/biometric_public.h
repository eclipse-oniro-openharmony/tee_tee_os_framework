/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: biometric_public function
 * Author: yww
 * Create: 2019-12-12
 */
#ifndef _BIOMETRIC_PUBLIC_H_
#define _BIOMETRIC_PUBLIC_H_

#include "tee_defines.h"

#define WEAK __attribute__((weak))
typedef void (*func_ptr)(void);
/* the num secn flash ipc cmd should begin 0x3100 */
enum BIOMETRIC_IPC_MSG_CMD {
    BIO_MSG_EXT_LOAD_CMD        = 0x6100,
    BIO_MSG_EXT_INSTALL_CMD,
    BIO_MSG_EXT_START_CMD,
    BIO_MSG_EXT_SEND_CMD,
    BIO_MSG_EXT_CLOSE_CMD,
    BIO_MSG_EXT_REINIT_CMD
};

TEE_Result TEE_EXT_BioLoadSA(const char *sa_image, uint32_t image_length);
TEE_Result TEE_EXT_BioInstallSA(uint32_t nvm_data_size, uint32_t version, uint16_t *sa_lfc);
TEE_Result TEE_EXT_BioStartSA();
TEE_Result TEE_EXT_BioSendCommand(uint8_t *apdu_buffer, uint32_t apdu_length, uint8_t *out_buffer,
                                  uint32_t *out_length);
TEE_Result TEE_EXT_BioCloseSA(void);
TEE_Result TEE_EXT_BioReInit(void);

#endif
