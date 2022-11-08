/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
