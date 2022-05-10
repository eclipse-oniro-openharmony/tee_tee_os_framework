/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: soft engine of boringssl
 * Create: 2022-03-30
 */
#include <stdbool.h>
#include <securec.h>
#include <tee_log.h>
#include "crypto_inner_interface.h"

int32_t recover_root_cert(uint8_t *cert, uint32_t cert_len, const void *priv, uint32_t keytype)
{
    (void)cert;
    (void)cert_len;
    (void)priv;
    (void)keytype;
    tloge("mix system do not support recover root cert\n");
    return -1;
}

int32_t sign_pkcs10(uint8_t *cert, uint32_t cert_len,
                    const uint8_t *csr, uint32_t csr_len, const validity_period_t *valid,
                    const uint8_t *serial_number, uint32_t serial_length, const void *priv, uint32_t keytype)
{
    (void)cert;
    (void)cert_len;
    (void)csr;
    (void)csr_len;
    (void)valid;
    (void)serial_number;
    (void)serial_length;
    (void)priv;
    (void)keytype;
    return -1;
}
