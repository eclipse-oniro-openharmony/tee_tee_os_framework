/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: kms secure hardware extensions function
 * Create: 2022-1-25
 */

#include "she.h"
#include "securec.h"
#include "kms_tag_api.h"
#include "kms_pub_def.h"
#include "tee_log.h"
#include "kms_key_storage.h"
#include "crypto_operation.h"
#include "gp_api_adapt_util.h"
#include "gp_api_adaptation.h"

static const uint8_t key_update_enc_c[] = { 0x01, 0x01, 0x53, 0x48, 0x45, 0x00 };
static const uint8_t key_update_mac_c[] = { 0x01, 0x02, 0x53, 0x48, 0x45, 0x00 };
static const uint8_t m4_plain_mask[] = { 0x00, 0x00, 0x00, 0x08 };

static TEE_Result mp_aes128_enc(TEE_ObjectHandle key_obj, struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    TEE_OperationHandle crypto_oper = NULL;
    TEE_Result ret = TEE_AllocateOperation(&crypto_oper, TEE_ALG_AES_ECB_NOPAD, TEE_MODE_ENCRYPT, MP_AES_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("mp aes enc: allocate operation fail\n");
        goto mem_free;
    }
    ret = TEE_SetOperationKey(crypto_oper, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("mp aes enc: set OperationKey fail 0x%x\n", ret);
        goto mem_free;
    }
    TEE_CipherInit(crypto_oper, NULL, 0);
    size_t out_len = out_data->length;
    ret = TEE_CipherDoFinal(crypto_oper, in_data->buffer, in_data->length, out_data->buffer, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("mp aes enc: crypto fail return = 0x%x\n", ret);
        goto mem_free;
    }
    out_data->length = out_len;
mem_free:
    if (crypto_oper != NULL) {
        TEE_FreeOperation(crypto_oper);
        crypto_oper = NULL;
    }
    return ret;
}

static TEE_Result mp_round_enc(const struct kms_buffer_data *round_key, struct kms_buffer_data *in_data,
    struct kms_buffer_data *out_data)
{
    TEE_ObjectHandle key_obj = NULL;
    TEE_Result ret = TEE_AllocateTransientObject(TEE_TYPE_AES, MP_AES_KEY_SIZE, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("mp round enc: alloc key obj fail\n");
        return ret;
    }
    ret = import_symmetry_key(round_key, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("mp round enc: set round key fail\n");
        goto mem_free;
    }
    ret = mp_aes128_enc(key_obj, in_data, out_data);
    if (ret != TEE_SUCCESS) {
        tloge("mp round enc: round enc fail\n");
        goto mem_free;
    }
    if (in_data->length != round_key->length || out_data->length != round_key->length) {
        tloge("mp round enc: unexpect indata length: 0x%x or outdata length 0x%x\n", in_data->length, out_data->length);
        ret = TEE_ERROR_GENERIC;
        goto mem_free;
    }
    for (uint32_t i = 0; i < out_data->length; i++)
        out_data->buffer[i] = (out_data->buffer[i] ^ in_data->buffer[i] ^ round_key->buffer[i]);
mem_free:
    if (key_obj != NULL) {
        TEE_FreeTransientObject(key_obj);
        key_obj = NULL;
    }
    return ret;
}

static TEE_Result mp_last_round_enc(struct kms_buffer_data *round_key, const struct kms_buffer_data *remain_data,
    struct kms_buffer_data *out_data, uint32_t messages_len)
{
    TEE_Result ret;
    uint8_t in[MP_BLOCK_SIZE] = { 0 };
    struct kms_buffer_data in_data = { MP_BLOCK_SIZE, in };
    uint64_t data_bit_len = (uint64_t)messages_len * BITS_PER_BYTE;
    if (remain_data->length >= MP_BLOCK_SIZE || data_bit_len > MP_MAX_MSG_BIT_LEN) {
        tloge("mp last round enc: invaild params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (remain_data->length > 0) {
        if (memcpy_s(in_data.buffer, in_data.length, remain_data->buffer, remain_data->length) != EOK) {
            tloge("mp last round enc: remain data copy faild\n");
            return TEE_ERROR_GENERIC;
        }
    }
    in_data.buffer[remain_data->length] = MP_PAD_START_BYTE;
    if (MP_BLOCK_SIZE - remain_data->length < MP_MIN_PAD_LEN) {
        /* need enc a round before pad messages length */
        ret = mp_round_enc(round_key, &in_data, out_data);
        if (ret != TEE_SUCCESS) {
            tloge("mp last round enc: remain data enc faild\n");
            return ret;
        }
        (void)memset_s(in_data.buffer, in_data.length, 0, in_data.length);
        if (memcpy_s(round_key->buffer, round_key->length, out_data->buffer, out_data->length) != EOK) {
            tloge("mp last round enc: get round key fail\n");
            return TEE_ERROR_GENERIC;
        }
    }
    /* pad messages length in last round */
    for (uint32_t i = 0; i < MP_PAD_MSG_LENGTH_LEN; i++)
        in_data.buffer[MP_BLOCK_MAX_OFFSET - i] = ((data_bit_len >> (BITS_PER_BYTE * i)) & 0xFF);

    ret = mp_round_enc(round_key, &in_data, out_data);
    if (ret != TEE_SUCCESS)
        tloge("mp last round enc: last round enc fail\n");
    return ret;
}

static TEE_Result mp_compression(uint8_t *messages, uint32_t length, uint8_t *output, uint32_t *output_length)
{
    TEE_Result ret;
    uint8_t key[MP_BLOCK_SIZE] = { 0 };
    uint8_t out[MP_BLOCK_SIZE] = { 0 };
    struct kms_buffer_data round_key = { MP_BLOCK_SIZE, key };
    struct kms_buffer_data in_data = { 0, NULL };
    struct kms_buffer_data out_data = { MP_BLOCK_SIZE, out };
    uint32_t i;
    for (i = 0; i < length / MP_BLOCK_SIZE; i++) {
        in_data.buffer = messages + (MP_BLOCK_SIZE * i);
        in_data.length = MP_BLOCK_SIZE;
        ret = mp_round_enc(&round_key, &in_data, &out_data);
        if (ret != TEE_SUCCESS) {
            tloge("mp compression: round enc fail\n");
            return ret;
        }
        if (memcpy_s(round_key.buffer, round_key.length, out_data.buffer, out_data.length) != EOK) {
            tloge("mp compression: get round key fail\n");
            return TEE_ERROR_GENERIC;
        }
    }
    in_data.buffer = messages + (MP_BLOCK_SIZE * i);
    in_data.length = length % MP_BLOCK_SIZE;
    ret = mp_last_round_enc(&round_key, &in_data, &out_data, length);
    if (ret != TEE_SUCCESS) {
        tloge("mp compression: last round enc fail\n");
        return ret;
    }
    if (memcpy_s(output, *output_length, out_data.buffer, out_data.length) != EOK) {
        tloge("mp compression: copy out data fail\n");
        return TEE_ERROR_GENERIC;
    }
    *output_length = out_data.length;
    return ret;
}

/*
 * it is a stub instead of get auth key from hsm
 */
#define STUB_AUTH_KEY_ID "soc_slot_id_3"
#define STUB_PARAM_COUNT 1
static TEE_Result she_get_auth_key(struct kms_buffer_data *auth_key)
{
    /* contract to read authkey from "soc_slot_id_3" before we can read it from hsm */
    struct kms_buffer_data key_blob = { 0, NULL };
    struct kms_buffer_data param_set = { 0, NULL };
    struct kms_buffer_data key_id;
    uint8_t key_id_buffer[] = { STUB_AUTH_KEY_ID };
    key_id.buffer = key_id_buffer;
    key_id.length = sizeof(key_id_buffer);
    TEE_Result ret = kms_get_key(&key_id, &key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("she get auth key: get key fail\n");
        goto mem_free;
    }
    param_set.buffer = (uint8_t *)TEE_Malloc(sizeof(uint32_t) + sizeof(struct kms_param_t), TEE_MALLOC_FILL_ZERO);
    *(uint32_t *)(param_set.buffer) = STUB_PARAM_COUNT;
    struct kms_param_t *param_key_type = (struct kms_param_t *)(param_set.buffer + sizeof(uint32_t));
    param_key_type->tag = KMS_TAG_KEY_TYPE;;
    param_key_type->data.integer = KMS_KEY_TYPE_AES;
    ret = kms_export_key(&param_set, auth_key, &key_blob);
    if (ret != TEE_SUCCESS)
        tloge("she get auth key: export key fail\n");

mem_free:
    kms_release_key(&key_id, &key_blob);
    if (param_set.buffer != NULL) {
        TEE_Free(param_set.buffer);
        param_set.buffer = NULL;
    }
    return ret;
}

TEE_Result she_derive_key(struct kms_buffer_data *key, struct kms_buffer_data *enc_key,
    struct kms_buffer_data *mac_key)
{
    TEE_Result ret;
    if (key->length > MAX_AUTH_KEY_LEN) {
        tloge("she derive key: invaild key length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *mp_messages = NULL;
    mp_messages = TEE_Malloc((key->length + sizeof(key_update_enc_c)), TEE_MALLOC_FILL_ZERO);
    (void)memcpy_s(mp_messages, key->length, key->buffer, key->length);
    (void)memcpy_s(mp_messages + key->length, sizeof(key_update_enc_c), key_update_enc_c, sizeof(key_update_enc_c));
    ret = mp_compression(mp_messages, (key->length + sizeof(key_update_enc_c)), enc_key->buffer, &(enc_key->length));
    TEE_Free(mp_messages);
    mp_messages = NULL;
    if (ret != TEE_SUCCESS) {
        tloge("she derive key: get enc key fail\n");
        return ret;
    }
    mp_messages = TEE_Malloc((key->length + sizeof(key_update_mac_c)), TEE_MALLOC_FILL_ZERO);
    (void)memcpy_s(mp_messages, key->length, key->buffer, key->length);
    (void)memcpy_s(mp_messages + key->length, sizeof(key_update_mac_c), key_update_mac_c, sizeof(key_update_mac_c));
    ret = mp_compression(mp_messages, (key->length + sizeof(key_update_mac_c)), mac_key->buffer, &(mac_key->length));
    TEE_Free(mp_messages);
    mp_messages = NULL;
    if (ret != TEE_SUCCESS)
        tloge("she derive key: get mac key fail\n");
    return ret;
}

void she_opera_free(struct she_opera_input *soi)
{
    if (soi == NULL)
        return;
    TEE_Free(soi);
}

static TEE_Result she_opera_init(const struct kms_buffer_data *param_set, struct she_opera_input *soi)
{
    struct kms_buffer_data she_m1;
    TEE_Result ret = get_key_param(&she_m1, KMS_TAG_SHE_MODE_EXPORT_M1, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("she opera init: get m1 failed\n");
        return ret;
    }
    struct kms_buffer_data she_m2_input;
    ret = get_key_param(&she_m2_input, KMS_TAG_SHE_MODE_EXPORT_M2_INPUT, param_set);
    if (ret != TEE_SUCCESS) {
        tloge("she opera init: get m2 input failed\n");
        return ret;
    }
    if ((she_m1.length != SHE_M1_LENGTH) || (she_m2_input.length != SHE_M2_HEADER_LENGTH)) {
        tloge("she opera init: invalid m1 or m2 input length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((memcpy_s(soi->m1, sizeof(soi->m1), she_m1.buffer, she_m1.length) != EOK) ||
        (memcpy_s(soi->m2_header, sizeof(soi->m2_header), she_m2_input.buffer, she_m2_input.length) != EOK)) {
        tloge("she opera init: copy m1 or m2 failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result she_aes_prepare(TEE_OperationHandle *crypto_oper,
    struct kms_buffer_data *key, uint32_t mode)
{
    TEE_ObjectHandle key_obj = NULL;
    TEE_Result ret = TEE_AllocateTransientObject(TEE_TYPE_AES, key->length * BITS_PER_BYTE, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("she aes operation: alloc key obj fail\n");
        return ret;
    }
    ret = import_symmetry_key(key, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("she aes operation: set round key fail\n");
        goto mem_free;
    }
    if (mode == TEE_MODE_ENCRYPT)
        ret = TEE_AllocateOperation(crypto_oper, TEE_ALG_AES_CBC_NOPAD, TEE_MODE_ENCRYPT, key->length * BITS_PER_BYTE);
    else
        ret = TEE_AllocateOperation(crypto_oper, TEE_ALG_AES_CMAC, TEE_MODE_MAC, key->length * BITS_PER_BYTE);
    if (ret != TEE_SUCCESS) {
        tloge("she aes operation: allocate operation fail\n");
        goto mem_free;
    }
    ret = TEE_SetOperationKey(*crypto_oper, key_obj);
    if (ret != TEE_SUCCESS)
        tloge("she aes operation: set OperationKey fail 0x%x\n", ret);
mem_free:
    if (key_obj != NULL) {
        TEE_FreeTransientObject(key_obj);
        key_obj = NULL;
    }
    return ret;
}
static TEE_Result she_aes_clac(TEE_OperationHandle crypto_oper, uint32_t mode,
    struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    size_t out_len = out_data->length;
    TEE_Result ret;
    if (mode == TEE_MODE_ENCRYPT) {
        uint8_t iv[SHE_BLOCK_LEN] = { 0 };
        TEE_CipherInit(crypto_oper, iv, SHE_BLOCK_LEN);
        ret = TEE_CipherDoFinal(crypto_oper, in_data->buffer, in_data->length, out_data->buffer, &out_len);
    } else {
        TEE_MACInit(crypto_oper, NULL, 0);
        ret = TEE_MACComputeFinal(crypto_oper, in_data->buffer, in_data->length, out_data->buffer, &out_len);
    }
    if (ret != TEE_SUCCESS) {
        tloge("she aes operation: crypto fail return = 0x%x\n", ret);
        return ret;
    }
    out_data->length = out_len;
    return ret;
}

/*
 * secure_data: M1 || M2 || M3
 */
static TEE_Result she_aes_operation(struct kms_buffer_data *key, uint32_t mode,
    struct kms_buffer_data *in_data, struct kms_buffer_data *out_data)
{
    if (mode != TEE_MODE_ENCRYPT && mode != TEE_MODE_MAC) {
        tloge("she aes operation: invalid mode\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_OperationHandle crypto_oper = NULL;
    TEE_Result ret = she_aes_prepare(&crypto_oper, key, mode);
    if (ret != TEE_SUCCESS) {
        tloge("she aes operation: aes prepare failed\n");
        goto mem_free;
    }
    ret = she_aes_clac(crypto_oper, mode, in_data, out_data);
    if (ret != TEE_SUCCESS)
        tloge("she aes operation: aes clac failed");
mem_free:
    if (crypto_oper != NULL) {
        TEE_FreeOperation(crypto_oper);
        crypto_oper = NULL;
    }
    return ret;
}

static TEE_Result she_clac_m2(struct kms_buffer_data *k1, struct she_opera_input *soi,
    struct kms_buffer_data *export_key, struct kms_buffer_data *m2)
{
    uint8_t m2_plain_buffer[SHE_M2_LENGTH] = { 0 };
    struct kms_buffer_data m2_plain = { sizeof(m2_plain_buffer), m2_plain_buffer };
    if (m2_plain.length != SHE_M2_HEADER_LENGTH + export_key->length) {
        tloge("she clac m2: invalid length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((memcpy_s(m2_plain.buffer, m2_plain.length, soi->m2_header, SHE_M2_HEADER_LENGTH) != EOK) ||
        (memcpy_s(m2_plain.buffer + SHE_M2_HEADER_LENGTH, m2_plain.length - SHE_M2_HEADER_LENGTH,
        export_key->buffer, export_key->length) != EOK)) {
        tloge("she clac m2: connect m2 plaintext fail\n");
        return TEE_ERROR_GENERIC;
    }
    return she_aes_operation(k1, TEE_MODE_ENCRYPT, &m2_plain, m2);
}

static TEE_Result she_clac_m3(struct kms_buffer_data *k2, struct kms_buffer_data *m1,
    struct kms_buffer_data *m2, struct kms_buffer_data *m3)
{
    uint8_t m3_plain_buffer[SHE_M1_LENGTH + SHE_M2_LENGTH] = { 0 };
    struct kms_buffer_data m3_plain = { sizeof(m3_plain_buffer), m3_plain_buffer };
    if (m3_plain.length != m1->length + m2->length) {
        tloge("she clac m3: invalid length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((memcpy_s(m3_plain.buffer, m3_plain.length, m1->buffer, m1->length) != EOK) ||
        (memcpy_s(m3_plain.buffer + m1->length, m3_plain.length - m1->length, m2->buffer, m2->length) != EOK)) {
        tloge("she clac m3: connect m3 plaintext fail\n");
        return TEE_ERROR_GENERIC;
    }
    return she_aes_operation(k2, TEE_MODE_MAC, &m3_plain, m3);
}

static TEE_Result she_clac_m4(struct kms_buffer_data *k3, struct she_opera_input *soi, struct kms_buffer_data *m4)
{
    uint8_t m4_plain_buffer[SHE_M4_ENC_LENGTH] = { 0 };
    struct kms_buffer_data m4_plain = { sizeof(m4_plain_buffer), m4_plain_buffer };
    if (((sizeof(soi->m2_header) != m4_plain.length) || (sizeof(soi->m2_header) < sizeof(m4_plain_mask)))) {
        tloge("she clac m4: invalid length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    for (uint32_t i = 0; i < sizeof(m4_plain_mask); i++)
        m4_plain.buffer[i] = (soi->m2_header[i] | m4_plain_mask[i]);
    if (memcpy_s(m4->buffer, m4->length, soi->m1, sizeof(soi->m1)) != EOK) {
        tloge("she clac m4: copy m1 failed\n");
        return TEE_ERROR_GENERIC;
    }
    struct kms_buffer_data m4_cipher;
    m4_cipher.buffer = m4->buffer + sizeof(soi->m1);
    m4_cipher.length = m4->length - sizeof(soi->m1);
    TEE_Result ret = she_aes_operation(k3, TEE_MODE_ENCRYPT, &m4_plain, &m4_cipher);
    if (ret != TEE_SUCCESS) {
        tloge("she clac m4: clac m4 cipher failed\n");
        return ret;
    }
    m4->length = sizeof(soi->m1) + m4_cipher.length;
    return ret;
}

static TEE_Result she_clac_m5(struct kms_buffer_data *k4, struct kms_buffer_data *m4, struct kms_buffer_data *m5)
{
    return she_aes_operation(k4, TEE_MODE_MAC, m4, m5);
}

static TEE_Result she_secure_data_generate(struct kms_buffer_data *gp_key_blob, const struct kms_buffer_data *param_set,
    struct she_opera_input *soi, struct kms_buffer_data *secure_data)
{
    TEE_Result ret = she_opera_init(param_set, soi);
    if (ret != TEE_SUCCESS) {
        tloge("she export key: opera init fail\n");
        return ret;
    }
    struct she_key key = { { 0 }, { 0 }, { 0 }, { 0 } };
    struct kms_buffer_data auth_key = { sizeof(key.auth_key_buffer), key.auth_key_buffer };
    struct kms_buffer_data k1 = { sizeof(key.enc_key_buffer), key.enc_key_buffer };
    struct kms_buffer_data k2 = { sizeof(key.mac_key_buffer), key.mac_key_buffer };
    struct kms_buffer_data export_key = { sizeof(key.export_key_buffer), key.export_key_buffer };
    ret = she_get_auth_key(&auth_key);
    if (ret != TEE_SUCCESS) {
        tloge("she gen sec data: get auth key failed\n");
        return ret;
    }
    ret = she_derive_key(&auth_key, &k1, &k2);
    if (ret != TEE_SUCCESS) {
        tloge("she gen sec data: derive k1&k2 failed\n");
        return ret;
    }
    ret = gp_export_key(param_set, &export_key, gp_key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("she gen sec data: get export key fail\n");
        return ret;
    }
    struct she_export_output output = { { 0 }, { 0 }, { 0 } };
    struct kms_buffer_data m1 = { sizeof(output.m1_buffer), output.m1_buffer };
    struct kms_buffer_data m2 = { sizeof(output.m2_buffer), output.m2_buffer };
    struct kms_buffer_data m3 = { sizeof(output.m3_buffer), output.m3_buffer };
    if (memcpy_s(m1.buffer, m1.length, soi->m1, sizeof(soi->m1)) != EOK)
        return TEE_ERROR_GENERIC;
    ret = she_clac_m2(&k1, soi, &export_key, &m2);
    if (ret != TEE_SUCCESS) {
        tloge("she gen sec data: clac m2 failed\n");
        return ret;
    }
    ret = she_clac_m3(&k2, &m1, &m2, &m3);
    if (ret != TEE_SUCCESS) {
        tloge("she gen sec data: clac m2 failed\n");
        return ret;
    }
    if (memcpy_s(secure_data->buffer, secure_data->length, &output, sizeof(output)) != EOK) {
        tloge("she gen sec data: cat secure data failed\n");
        return TEE_ERROR_GENERIC;
    }
    secure_data->length = sizeof(output);
    return TEE_SUCCESS;
}

static TEE_Result she_verify_m1(struct she_opera_input *soi, struct kms_buffer_data *verify_data)
{
    /*
     * M1: UID || ID || AuthId
     * M4: UID || ID || AuthId || ENCECB(K3){ Counter | 1 | "0..0" }
     * Normally the UID in M4 and M1 should be the same
     * but when UID in M1 is "0..0", use UID in M4 to verify
     */
    if ((sizeof(soi->m1) <= SHE_COUNTER_LENGTH) || (verify_data->length < sizeof(soi->m1))) {
        tloge("she verify m1: invalid verify data length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_MemCompare(soi->m1, verify_data->buffer, sizeof(soi->m1)) == 0)
        return TEE_SUCCESS;
    uint8_t tmp[SHE_COUNTER_LENGTH] = { 0 };
    if ((TEE_MemCompare(soi->m1, tmp, SHE_COUNTER_LENGTH) == 0) &&
        (TEE_MemCompare(soi->m1 + SHE_COUNTER_LENGTH, verify_data->buffer + SHE_COUNTER_LENGTH,
        sizeof(soi->m1) - SHE_COUNTER_LENGTH) == 0)) {
        if (memcpy_s(soi->m1, sizeof(soi->m1), verify_data->buffer, SHE_COUNTER_LENGTH) != EOK) {
            tloge("she verify m1: copy m1 failed\n");
            return TEE_ERROR_GENERIC;
        }
        return TEE_SUCCESS;
    }
    tloge("she verify m1: unexpect m1 in verify data\n");
    return (TEE_Result)KMS_ERROR_VERIFICATION_FAILED;
}

/*
 * verify_data: M4 || M5
 */
static TEE_Result she_secure_data_verify(struct kms_buffer_data *gp_key_blob, const struct kms_buffer_data *param_set,
    struct she_opera_input *soi, struct kms_buffer_data *verify_data)
{
    if (verify_data->length != sizeof(struct she_verify_expect)) {
        tloge("she verify sec data: invalid verify data length\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    TEE_Result ret = she_verify_m1(soi, verify_data);
    if (ret != TEE_SUCCESS) {
        tloge("she verify sec data: verify m1 failed\n");
        return ret;
    }
    struct she_key key = { { 0 }, { 0 }, { 0 }, { 0 } };
    struct kms_buffer_data k3 = { sizeof(key.enc_key_buffer), key.enc_key_buffer };
    struct kms_buffer_data k4 = { sizeof(key.mac_key_buffer), key.mac_key_buffer };
    struct kms_buffer_data export_key = { sizeof(key.export_key_buffer), key.export_key_buffer };
    ret = gp_export_key(param_set, &export_key, gp_key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("she verify sec data: get export key fail\n");
        return ret;
    }
    ret = she_derive_key(&export_key, &k3, &k4);
    if (ret != TEE_SUCCESS) {
        tloge("she verify sec data: derive k3&k4 failed\n");
        return ret;
    }
    struct she_verify_expect expect = { { 0 }, { 0 } };
    struct kms_buffer_data m4 = { sizeof(expect.m4_buffer), expect.m4_buffer };
    struct kms_buffer_data m5 = { sizeof(expect.m5_buffer), expect.m5_buffer };
    ret = she_clac_m4(&k3, soi, &m4);
    if (ret != TEE_SUCCESS) {
        tloge("she verify sec data: clac m4 failed\n");
        return ret;
    }
    ret = she_clac_m5(&k4, &m4, &m5);
    if (ret != TEE_SUCCESS) {
        tloge("she verify sec data: clac m5 failed\n");
        return ret;
    }
    if (TEE_MemCompare(verify_data->buffer, &expect, verify_data->length) != 0) {
        tloge("she verify sec data: verify failed\n");
        return (TEE_Result)KMS_ERROR_VERIFICATION_FAILED;
    }
    return TEE_SUCCESS;
}

TEE_Result she_export_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *opt_handle,
    struct kms_buffer_data *gp_key_blob, struct kms_buffer_data *out_key)
{
    struct kms_key_node *key_node = NULL;
    struct she_opera_input *soi = TEE_Malloc(sizeof(struct she_opera_input), TEE_MALLOC_FILL_ZERO);
    if (soi == NULL) {
        tloge("she export key: malloc fail\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_Result ret = she_secure_data_generate(gp_key_blob, param_set, soi, out_key);
    if (ret != TEE_SUCCESS) {
        tloge("she export key: gen sec data fail\n");
        return ret;
    }
    key_node = alloc_init_key_node(SHE_EXPORT, ENGINE_TYPE_GP);
    if (key_node == NULL) {
        tloge("she export key:alloc key node fail\n");
        ret = TEE_ERROR_GENERIC;
        goto error_free;
    }
    key_node->key_operate = (void *)soi;
    errno_t rc = memcpy_s(opt_handle->buffer, opt_handle->length, &key_node->opt_handle, sizeof(key_node->opt_handle));
    if (rc != EOK) {
        tloge("she export key: copy handle fail\n");
        ret = TEE_ERROR_GENERIC;
        goto error_free;
    }
    opt_handle->length = sizeof(key_node->opt_handle);
    /* this func must run in last, or if run has error after this fun,
     * need call delete_free_key_node and set key_node to null
     */
    ret = add_key_node(key_node);
    if (ret != TEE_SUCCESS) {
        tloge("she export key: add key node fail\n");
        goto error_free;
    }
    return TEE_SUCCESS;
error_free:
    she_opera_free(soi);
    soi = NULL;
    if (key_node != NULL) {
        TEE_Free(key_node);
        key_node = NULL;
    }
    return ret;
}

TEE_Result she_verify_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *opt_handle,
    struct kms_buffer_data *gp_key_blob, struct kms_buffer_data *verify_data)
{
    uint64_t handle = *(uint64_t *)opt_handle->buffer;
    TEE_Result ret = set_ophandle_state(handle, USING);
    if (ret != TEE_SUCCESS) {
        tloge("she verify: set ophandle state %u failed, ret = 0x%x\n", USING, ret);
        return ret;
    }
    struct kms_key_node *key_node = NULL;
    ret = get_key_node(handle, &key_node);
    if (ret != TEE_SUCCESS) {
        tloge("she verify: can't get keynode by handle 0x%llx\n", handle);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key_node->node_type != SHE_EXPORT) {
        tloge("she verify: node type error, used a wrong handle\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto mem_free;
    }
    struct she_opera_input *soi = (struct she_opera_input *)key_node->key_operate;
    if (soi == NULL) {
        tloge("she verify: soi is null, secure export may be error\n");
        ret = TEE_ERROR_BAD_STATE;
        goto mem_free;
    }
    ret = she_secure_data_verify(gp_key_blob, param_set, soi, verify_data);
    if (ret != TEE_SUCCESS)
        tloge("she verify: data verify fail\n");

mem_free:
    she_opera_free(key_node->key_operate);
    key_node->key_operate = NULL;
    TEE_Result free_ret = delete_free_key_node(handle);
    if (free_ret != TEE_SUCCESS) {
        /* this should never fail, otherwise this node memory could not be freeed */
        tloge("she verify: delete key node fail, may memory leak, free_ret = 0x%x, ret = 0x%x\n", free_ret, ret);
        ret = (ret == TEE_SUCCESS) ? free_ret : ret;
    }
    return ret;
}
