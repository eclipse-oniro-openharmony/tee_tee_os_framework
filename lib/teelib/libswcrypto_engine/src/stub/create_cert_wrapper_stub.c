/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: soft engine stub of boringssl
 * Create: 2022-03-30
 */
#include <stdbool.h>
#include <securec.h>
#include <tee_log.h>
#include "crypto_inner_interface.h"

int32_t get_tbs_element(uint8_t **elem, uint32_t elem_id, const uint8_t *cert, uint32_t cert_len)
{
    (void)elem;
    (void)elem_id;
    (void)cert;
    (void)cert_len;
    return -1;
}

int32_t create_attestation_cert(uint8_t *cert, uint32_t cert_len, const validity_period_t *valid,
                                const uint8_t *issuer_tlv, uint32_t issuer_tlv_len,
                                const uint8_t *subject_public_key, uint32_t subject_public_key_len,
                                const uint8_t *attestation_ext, uint32_t attestation_ext_len, void *priv_sign,
                                uint32_t key_usage_sign_bit, uint32_t key_usage_encrypt_bit, uint32_t key_type,
                                uint32_t hash)
{
    (void)cert;
    (void)cert_len;
    (void)valid;
    (void)issuer_tlv;
    (void)issuer_tlv_len;
    (void)subject_public_key;
    (void)subject_public_key_len;
    (void)attestation_ext;
    (void)attestation_ext_len;
    (void)priv_sign;
    (void)key_usage_sign_bit;
    (void)key_usage_encrypt_bit;
    (void)key_type;
    (void)hash;
    return -1;
}
