/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Partial calculate implementation of the GP functions.
 * Author: aaron.shen
 * Create: 2019/08/20
 */

#include "secflash_scp03_calc.h"
#include "openssl/evp.h"
#ifndef BORINGSSL_ENABLE
#include "openssl/ossl_typ.h"
#include <evp/evp_local.h>
#endif
#include "openssl/aes.h"
#include "openssl/cmac.h"
#include "tee_log.h"
#include "securec.h"
#include "tee_crypto_api.h"

#if SECFLASH_DEBUG
#define MAX_DUMP_DATA_LEN                 512

void dump_data(char *info, uint8_t *data, uint16_t len)
{
    uint16_t i;
    uint16_t print_len;

    if (!info || !data)
        return;

    tloge("%s (len=%x) :", info, len);
    /* dump 512 bytes data only */
    print_len = (len > MAX_DUMP_DATA_LEN) ? MAX_DUMP_DATA_LEN : len;
    for (i = 0; i < print_len; i++)
        tloge("%02x", data[i]);
}
#endif

/*
 * @brief     : supply the AES-CBC calc.
 * @param[in] : value, a pointer to the crypto info, such as key/datain/dataout etc.
 * @return    : success of failure
 */
static uint32_t secflash_crypto_aes(struct crypto_info *value)
{
    uint32_t boringssl_mode;
    EVP_CIPHER_CTX context = {0};
    int32_t dest_len;
    int32_t final_len;
    int32_t ret;
    uint32_t status = SECFLASH_SUCCESS;

    if (!value || !value->iv || !value->key || !value->data_in || !value->data_out) {
        tloge("%s, Err invalid input\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    if (value->data_in_size % SECFLASH_BLOCK_BYTE_LEN) {
        tloge("%s, input length failed:%x\n", __func__, value->data_in_size);
        return SECFLASH_FAILURE | INPUT_LEN_ERR;
    }

    if (value->operation_mode == TEE_MODE_ENCRYPT) {
        boringssl_mode = 1; /* ENCRYPTION MODE */
    } else {
        boringssl_mode = 0; /* DECRYPTION MODE */
    }

    ret = EVP_CipherInit(&context, EVP_aes_128_cbc(), value->key, value->iv, boringssl_mode);
    if (ret != 1) {
        tloge("%s, set aes cbc key failed:%x\n", __func__, ret);
        status = SECFLASH_FAILURE | AES_INPUT_KEY_ERR;
        goto clean;
    }

    if (value->crypto_algo == TEE_ALG_AES_CBC_NOPAD)
        (void)EVP_CIPHER_CTX_set_padding(&context, 0); /* no padding */
    else
        (void)EVP_CIPHER_CTX_set_padding(&context, 1);

    dest_len = (int32_t)value->data_in_size;
    ret = EVP_CipherUpdate(&context, value->data_out, &dest_len, value->data_in, value->data_in_size);
    if (ret != 1) {
        tloge("%s, set aes cbc update failed:%x\n", __func__, ret);
        status = SECFLASH_FAILURE | AES_INIT_ERR;
        goto clean;
    }

    final_len = (int32_t)value->data_in_size;
    ret = EVP_CipherFinal_ex(&context, value->data_out + dest_len, &final_len);
    if (ret != 1) {
        tloge("%s, set aes cbc dofinal failed:%x\n", __func__, ret);
        status = SECFLASH_FAILURE | AES_DOFINAL_ERR;
        goto clean;
    }

clean:
    EVP_CIPHER_CTX_cleanup(&context);
    return status;
}

/*
 * @brief     : supply the CC AES-CMAC crypto function.
 * @param[in] : key, a pointer to a key that is used in crypto,
 *              key_size, the key byte size,
 *              data_in, a pointer to the data
 *              data_in_size, the data size in bytes.
 *              max_data_out_size, the data out buffer max size.
 * @param[out]: data_out, the pointer of the aes out data.
 * @return    : success of failure
 */
static uint32_t secflash_crypto_aes_cmac(struct crypto_info *value)
{
    CMAC_CTX *cmac_ctx = NULL;
    int32_t rc;
    size_t temp_out_size = 0;
    uint32_t ret;
    uint32_t status = SECFLASH_SUCCESS;

    if (!value || !value->key || !value->data_in || !value->data_out)
        return SECFLASH_FAILURE | POINTER_NULL;

    if (value->key_size != AES_BLOCK_SIZE)
        return SECFLASH_FAILURE | AES_INPUT_KEY_ERR;

    if (value->max_data_out_size < value->key_size) {
        tloge("%s, datalength%x failed:%x\n", __func__, value->max_data_out_size);
        return SECFLASH_FAILURE | AES_INPUT_DATA_ERR;
    }

    cmac_ctx = CMAC_CTX_new();
    if (!cmac_ctx) {
        tloge("%s, aes cmac new failed:%x\n", __func__, cmac_ctx);
        return SECFLASH_FAILURE | AES_INIT_ERR;
    }

    ret = memset_s(value->data_out, value->max_data_out_size, 0, AES_BLOCK_SIZE);
    if (ret != EOK) {
        tloge("%s, memset failed.\n", __func__);
        status = SECFLASH_FAILURE | MEMCPY_ERR;
        goto cmac_end;
    }

    rc = CMAC_Init(cmac_ctx, value->key, AES_BLOCK_SIZE, EVP_aes_128_cbc(), 0);
    if (rc != 1) {
        tloge("%s,  aes cmac init failed:%x\n", __func__, rc);
        status = SECFLASH_FAILURE | AES_INIT_ERR;
        goto cmac_end;
    }

    rc = CMAC_Update(cmac_ctx, value->data_in, value->data_in_size);
    if (rc != 1) {
        tloge("%s, aes cmac update failed:%x\n", __func__, rc);
        status = SECFLASH_FAILURE | AES_UPDATE_ERR;
        goto cmac_end;
    }

    rc = CMAC_Final(cmac_ctx, value->data_out, &temp_out_size);
    if (rc != 1) {
        tloge("%s, aes cmac dofinal failed:%x\n", __func__, rc);
        status = SECFLASH_FAILURE | AES_DOFINAL_ERR;
        goto cmac_end;
    }

cmac_end:
    if (cmac_ctx)
        CMAC_CTX_free(cmac_ctx);

    return status;
}

/*
 * @brief     : SCP03 kdf function (the PRF shall be CMAC and key length is 128bits)
 * @param[in] : derivation_constant, one byte in a string that identifies the purpose
 *                                   for the derived keying material,
 *              l, specifying the length in bits of the derived data,
 *              context, a pointer to the binary string containing the
 *                       information related to the derived keying material,
 *              key_in, a pointer to a key that is used as an input to a
 *                      key derivation function to derive keying material,
 *              derived_data, the data buffer and length of derived_data.
 * @param[out]: derived_data, output from a key derivation.
 * @return    : success of failure
 */
static uint32_t secflash_compute_kdf(uint8_t derivation_constant, uint16_t l, uint8_t *context,
    uint8_t *key_in, struct data_info derived_data)
{
    uint8_t kdf_message[SECFLASH_KDF_MESSAGE_LEN] = {0};
    struct crypto_info value = {0};
    uint32_t ret;
    uint32_t status;

    if (!context || !derived_data.data) {
        tloge("%s invalid params.\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    (void)memset_s(&kdf_message[0], SECFLASH_KDF_MESSAGE_LEN, 0, SECFLASH_KDF_MESSAGE_LEN);
    /* 11 bytes with value '00' followed by a one byte derivation constant */
    kdf_message[SECFLASH_LABLE_LEN - 1] = derivation_constant;
    /* separation indicator */
    kdf_message[SECFLASH_LABLE_LEN] = 0;
    /* 2 byte integer 'L' */
    kdf_message[SECFLASH_LABLE_LEN + ONE_BYTES_OFFSET] = (uint8_t)(l >> ONE_BYTE_BITS_OFFSET);
    kdf_message[SECFLASH_LABLE_LEN + TWO_BYTES_OFFSET] = (uint8_t)l;
    /* i: 0x01 */
    kdf_message[SECFLASH_LABLE_LEN + THREE_BYTES_OFFSET] = 0x1;
    /* context */
    ret = memcpy_s(&kdf_message[SECFLASH_LABLE_LEN + FOUR_BYTES_OFFSET],
                   SECFLASH_KDF_MESSAGE_LEN - SECFLASH_LABLE_LEN - FOUR_BYTES_OFFSET, context,
                   SECFLASH_KDF_CONTEXT_LEN);
    if (ret != EOK) {
        tloge("%s, memcpy_s failed.\n", __func__);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }

    value.key = key_in;
    value.key_size = SECFLASH_AES_KEY_BYTE_LEN;
    value.data_in = &kdf_message[0];
    value.data_in_size = SECFLASH_KDF_MESSAGE_LEN;
    value.data_out = derived_data.data;
    value.max_data_out_size = derived_data.data_length;
    status = secflash_crypto_aes_cmac(&value);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, crypto AES-CMAC failed: %x\n", __func__, status);
        return status;
    }

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : generate the AES session keys every time
 *              a Secure Channel is initiated.
 * @param[in] : key, the pointer of root key which used to derivate session key.
 *              host_challenge, the host challenge to be used.
 *              card_challenge, the received card challenge.
 *              session_key, the key pointer to be used.
 * @return    : success of failure
 */
uint32_t secflash_generate_session_keys(struct secflash_keyset *key, uint8_t *host_challenge,
    uint8_t *card_challenge, struct session_sec_channel_key *session_key)
{
    uint8_t derivation_constant;
    uint8_t context[SECFLASH_KDF_CONTEXT_LEN] = {0};
    struct data_info derived_data;
    int32_t ret;
    uint32_t status;

    if (!key || !host_challenge || !card_challenge || !session_key) {
        tloge("%s, key pointer NULL\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    ret = memcpy_s(&context[0], SECFLASH_KDF_CONTEXT_LEN, host_challenge, SECFLASH_CHALLENGE_LENGTH);
    ret += memcpy_s(&context[SECFLASH_CHALLENGE_LENGTH], SECFLASH_KDF_CONTEXT_LEN - SECFLASH_CHALLENGE_LENGTH,
                       card_challenge, SECFLASH_CHALLENGE_LENGTH);
    if (ret != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, ret);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }

    /* get session sec channel key */
    derivation_constant = SECFLASH_SCP03_DERIVATION_SENC;
    derived_data.data = &session_key->senc[0];
    derived_data.data_length = SECFLASH_AES_KEY_BYTE_LEN;
    status = secflash_compute_kdf(derivation_constant, SECFLASH_L_128BIT, context, &key->enc[0], derived_data);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, kdf calc senc err:%x\n", __func__, status);
        return SECFLASH_FAILURE | KDF_CALCULATE_ERR;
    }

    derivation_constant = SECFLASH_SCP03_DERIVATION_SMAC;
    derived_data.data = &session_key->smac[0];
    derived_data.data_length = SECFLASH_AES_KEY_BYTE_LEN;
    status = secflash_compute_kdf(derivation_constant, SECFLASH_L_128BIT, context, &key->mac[0], derived_data);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, kdf calc smac err:%x\n", __func__, status);
        return SECFLASH_FAILURE | KDF_CALCULATE_ERR;
    }

    derivation_constant = SECFLASH_SCP03_DERIVATION_SRMAC;
    derived_data.data = &session_key->srmac[0];
    derived_data.data_length = SECFLASH_AES_KEY_BYTE_LEN;
    status = secflash_compute_kdf(derivation_constant, SECFLASH_L_128BIT, context, &key->mac[0], derived_data);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, kdf calc srmac err:%x\n", __func__, status);
        return SECFLASH_FAILURE | KDF_CALCULATE_ERR;
    }

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : verify the card cryptogram get from security flash (card).
 * @param[in] : data, the pointer of challenge
 *              key, the pointer of key used in kdf calc.
 * @return    : success of failure
 */
uint32_t secflash_verify_card_cryptogram(struct scp_challenge *data, uint8_t *key)
{
    uint8_t derivation_constant;
    uint8_t context[SECFLASH_KDF_CONTEXT_LEN] = {0};
    uint8_t card_cryptogram[SECFLASH_CRYPTOGRAM_LENGTH] = {0};
    struct data_info derived_data;
    uint32_t status;

    if (!data || !key) {
        tloge("%s, Err verify card invalid input\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    derivation_constant = 0x00; /* SCP03 Table 4-1 */
    status = memcpy_s(&context[0], SECFLASH_KDF_CONTEXT_LEN, &data->host_challenge[0], SECFLASH_CHALLENGE_LENGTH);
    status = memcpy_s(&context[SECFLASH_CHALLENGE_LENGTH], SECFLASH_KDF_CONTEXT_LEN - SECFLASH_CHALLENGE_LENGTH,
                      &data->card_challenge[0], SECFLASH_CHALLENGE_LENGTH);
    if (status != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, status);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }
    derived_data.data = &card_cryptogram[0];
    derived_data.data_length = SECFLASH_CRYPTOGRAM_LENGTH;
    status = secflash_compute_kdf(derivation_constant, SECFLASH_L_64BIT, context, key, derived_data);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, kdf calc err:%x\n", __func__, status);
        return SECFLASH_FAILURE | KDF_CALCULATE_ERR;
    }

#if SECFLASH_DEBUG
    dump_data("Received card_cryptogram", &data->card_cryptogram[0], SECFLASH_CHALLENGE_LENGTH);
    dump_data("Calculated card_cryptogram", &card_cryptogram[0], SECFLASH_CHALLENGE_LENGTH);
#endif

    /* verify */
    if (memcmp(&data->card_cryptogram[0], &card_cryptogram[0], SECFLASH_CHALLENGE_LENGTH) == 0)
        return SECFLASH_SUCCESS;

    tloge("%s, verify Failed\n", __func__);
    return SECFLASH_FAILURE | VERIFY_ERR;
}

/*
 * @brief     : calculate the host cryptogram of host challenge.
 * @param[in] : data, the pointer of card/host challenge to be used.
 *              key, the key pointer to be used.
 * @return    : success of failure
 */
uint32_t secflash_calculate_host_cryptogram(struct scp_challenge *data, uint8_t *key)
{
    uint8_t derivation_constant;
    uint8_t context[SECFLASH_KDF_CONTEXT_LEN] = {0};
    uint8_t host_cryptogram[SECFLASH_CRYPTOGRAM_LENGTH] = {0};
    struct data_info derived_data;
    int32_t ret;
    uint32_t status;

    if (!data || !key) {
        tloge("%s, Err invalid input\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    derivation_constant = 0x01; /* host_cryptogram */
    ret = memcpy_s(&context[0], SECFLASH_KDF_CONTEXT_LEN, &data->host_challenge[0], SECFLASH_CHALLENGE_LENGTH);
    ret += memcpy_s(&context[SECFLASH_CHALLENGE_LENGTH], SECFLASH_KDF_CONTEXT_LEN - SECFLASH_CHALLENGE_LENGTH,
                       &data->card_challenge[0], SECFLASH_CHALLENGE_LENGTH);
    if (ret != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, ret);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }
    derived_data.data = &host_cryptogram[0];
    derived_data.data_length = SECFLASH_CRYPTOGRAM_LENGTH;
    status = secflash_compute_kdf(derivation_constant, SECFLASH_L_64BIT, context, key, derived_data);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, kdf calc err:%x\n", __func__, status);
        return SECFLASH_FAILURE | KDF_CALCULATE_ERR;
    }
    ret = memcpy_s(&data->host_cryptogram[0], SECFLASH_CHALLENGE_LENGTH, &host_cryptogram[0],
                      SECFLASH_CHALLENGE_LENGTH);
    if (ret != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, ret);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }
#if SECFLASH_DEBUG
    dump_data("Calculated host_cryptogram", &data->host_cryptogram[0], SECFLASH_CHALLENGE_LENGTH);
#endif
    return SECFLASH_SUCCESS;
}

/*
 * @brief     : calculate the data CMAC and modify the g_cmac_chaining value.
 * @param[in] : apdu_buf, the pointer of apdu field to be calculate;
 *              data_length, the apdu data field length;
 *              extended_length, the lc extended or not;
 *              mac_chaining_data, the data and length of g_mac_chaining;
 *              key, the pointer of key.
 * @return    : success of failure
 */
uint32_t secflash_calculate_cmac(uint8_t *apdu_buf, uint32_t data_length, uint8_t extended_length,
    struct data_info mac_chaining_data, uint8_t *key)
{
    uint8_t *cmd = NULL;
    uint16_t cmd_length;
    struct crypto_info value = {0};
    int32_t ret;
    uint32_t status;

    if (!apdu_buf || !mac_chaining_data.data || !key) {
        tloge("%s, calc cmac pointer NULL\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    /* max value is write cmd data length */
    if (data_length > SECFLASH_CMAC_CMD_MAX_LEN) {
        tloge("%s, input length err:%x\n", __func__, data_length);
        return SECFLASH_FAILURE | INPUT_LEN_ERR;
    }

    /*
    * MAC chaining value (16 bytes) + CLA...Lc(5+extended_length) +
    * Command data field
    */
    cmd_length = SECFLASH_CMAC_TOTAL_LENGTH + CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + data_length;
    cmd = TEE_Malloc(cmd_length, 0);
    if (!cmd) {
        tloge("%s, malloc err\n", __func__);
        return SECFLASH_FAILURE | MALLOC_ERR;
    }

    ret = memcpy_s(&cmd[0], cmd_length, mac_chaining_data.data, SECFLASH_CMAC_TOTAL_LENGTH);
    ret += memcpy_s(&cmd[SECFLASH_CMAC_TOTAL_LENGTH], cmd_length - SECFLASH_CMAC_TOTAL_LENGTH,
                       apdu_buf, cmd_length -  SECFLASH_CMAC_TOTAL_LENGTH);
    if (ret != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, ret);
        status = SECFLASH_FAILURE | MEMCPY_ERR;
        goto error_process;
    }

    value.key = key;
    value.key_size = SECFLASH_AES_KEY_BYTE_LEN;
    value.data_in = &cmd[0];
    value.data_in_size = cmd_length;
    value.data_out = mac_chaining_data.data;
    value.max_data_out_size = mac_chaining_data.data_length;
    status = secflash_crypto_aes_cmac(&value);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, crypto AES CMAC failed: %x\n", __func__, status);
        goto error_process;
    }

#if SECFLASH_DEBUG
    dump_data("Calculated cmac", mac_chaining_data.data, SECFLASH_CMAC_TOTAL_LENGTH);
#endif

    status = SECFLASH_SUCCESS;
error_process:
    TEE_Free(cmd);
    cmd = NULL;
    return status;
}

/*
 * @brief     : verify the RMAC get from security flash (card).
 * @param[in] : apdu_data_buf,  the pointer of apdu response data and R-MAC
 *              length, the apdu field length;
 *              mac_chaining, the pointer of g_mac_chaining.
 *              key, the pointer of key.
 * @return    : success of failure
 */
uint32_t secflash_verify_rmac(uint8_t *apdu_data_buf, uint32_t length, uint8_t *mac_chaining, uint8_t *key)
{
    uint8_t rmac[SECFLASH_CMAC_TOTAL_LENGTH] = {0};
    uint8_t *cmd = NULL;
    uint32_t cmd_length;
    uint32_t data_length;
    struct crypto_info value = {0};
    int32_t ret;
    uint32_t status;

    if (!apdu_data_buf || !mac_chaining || !key)
        return SECFLASH_FAILURE | POINTER_NULL;

    if (length < (SECFLASH_CMAC_LENGTH + GP_SW_LENGTH) || (length > SECFLASH_RMAC_DATA_MAX_LEN))
        return SECFLASH_FAILURE | INPUT_LEN_ERR;

    data_length = length - SECFLASH_CMAC_LENGTH - GP_SW_LENGTH;
    cmd_length = SECFLASH_CMAC_TOTAL_LENGTH + data_length + GP_SW_LENGTH;
    cmd = TEE_Malloc(cmd_length, 0);
    if (!cmd)
        return SECFLASH_FAILURE | MALLOC_ERR;

    /* copy mac chaining */
    ret = memcpy_s(&cmd[0], cmd_length, mac_chaining, SECFLASH_CMAC_TOTAL_LENGTH);
    /* copy data */
    ret += memcpy_s(&cmd[SECFLASH_CMAC_TOTAL_LENGTH], cmd_length - SECFLASH_CMAC_TOTAL_LENGTH,
                       apdu_data_buf, data_length);
    /* copy sw */
    ret += memcpy_s(&cmd[SECFLASH_CMAC_TOTAL_LENGTH + data_length], cmd_length - SECFLASH_CMAC_TOTAL_LENGTH -
                                                      data_length, &apdu_data_buf[length - GP_SW_LENGTH], GP_SW_LENGTH);
    if (ret != EOK) {
        status = SECFLASH_FAILURE | MEMCPY_ERR;
        goto error_process;
    }

    value.key = key;
    value.key_size = SECFLASH_AES_KEY_BYTE_LEN;
    value.data_in = &cmd[0];
    value.data_in_size = cmd_length;
    value.data_out = &rmac[0];
    value.max_data_out_size = SECFLASH_CMAC_TOTAL_LENGTH;
    status = secflash_crypto_aes_cmac(&value);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, crypto AES CMAC failed: %x\n", __func__, status);
        goto error_process;
    }

    /* verify */
    if (memcmp(&apdu_data_buf[data_length], &rmac[0], SECFLASH_CMAC_LENGTH) == 0) {
        status = SECFLASH_SUCCESS;
    } else {
        tloge("%s, rmac verify fail\n", __func__);
        status = SECFLASH_FAILURE | RMAC_VERIFY_ERR;
    }

error_process:
    TEE_Free(cmd);
    cmd = NULL;
    return status;
}

/*
 * @brief     :  encrypt the sensitive data which will be stored in secflash.
 * @param[in] :  info, the information of the sensitive data.
 *               iv, the Initial Vector pointer of AES-CBC calc.
 * @param[out]:  info->data, the pointer of encrypted data.
 * @return    :  success of failure
 */
uint32_t secflash_encrypt_sensitive_data(struct cmd_derivate_info *info, uint8_t *iv)
{
    uint16_t encrypt_iv[SECFLASH_IV_BYTE_LEN / sizeof(uint16_t)] = {0};
    uint8_t encrypt_key[SECFLASH_AES_KEY_BYTE_LEN] = {0};
    uint16_t context[SECFLASH_IV_BYTE_LEN / sizeof(uint16_t)] = {0};
    uint32_t data_length;
    struct crypto_info value = {0};
    uint32_t i;
    uint32_t j;
    uint32_t status;

    if (!info || !info->data || !iv) {
        tloge("%s, pointer NULL\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    data_length = SECFLASH_BLOCK_BYTE_LEN * info->block_count;
    if (data_length > info->max_data_buf) {
        tloge("%s, length err:%x\n", __func__, data_length);
        return SECFLASH_FAILURE | INPUT_LEN_ERR;
    }

    value.iv = (uint8_t *)&encrypt_iv[0];
    value.iv_size = SECFLASH_IV_BYTE_LEN;
    value.key = &encrypt_key[0];
    value.key_size = SECFLASH_AES_KEY_BYTE_LEN;
    value.crypto_algo = TEE_ALG_AES_CBC_NOPAD;
    value.operation_mode = TEE_MODE_ENCRYPT;
    for (i = 0; i < info->block_count; i++) { /* AES-XTS encrypt every 16bytes block data */
        for (j = 0; j < SECFLASH_IV_BYTE_LEN / sizeof(uint16_t); j++) { /* count is 8 */
            encrypt_iv[j] = ((uint16_t)iv[j]) ^ ((uint16_t)(info->phy_block_index + i));
            context[j] = (uint16_t)(info->phy_block_index + i);
        }
        status = secflash_aes_cmac_wrapper((uint8_t *)&context[0], SECFLASH_AES_KEY_BYTE_LEN, encrypt_key);
        if (status != SECFLASH_SUCCESS) {
            tloge("%s, generate encrypt key err:%x\n", __func__, status);
            goto error_process;
        }
        value.data_in = &info->data[i * SECFLASH_BLOCK_BYTE_LEN];
        value.data_in_size = SECFLASH_BLOCK_BYTE_LEN;
        value.data_out = &info->data_out[i * SECFLASH_BLOCK_BYTE_LEN];
        status = secflash_crypto_aes(&value);
        if (status != SECFLASH_SUCCESS) {
            tloge("%s, crypto AES failed: %x\n", __func__, status);
            goto error_process;
        }
    }

    status = SECFLASH_SUCCESS;

error_process:
    (void)memset_s(&encrypt_key[0], SECFLASH_AES_KEY_BYTE_LEN, 0, SECFLASH_AES_KEY_BYTE_LEN);
    (void)memset_s((uint8_t *)&encrypt_iv[0], SECFLASH_IV_BYTE_LEN, 0, SECFLASH_IV_BYTE_LEN);
    return status;
}

/*
 * @brief     :  decrypt the sensitive data which was read from secflash.
 * @param[in] :  info, the information of the sensitive data.
 *               iv, the Initial Vector pointer of AES-CBC calc.
 *               data_buf, the pointer of data field to be encrypt
 *               out_buf_length, the buffer length of out buf.
 * @param[out]:  out_buf, the pointer of encrypted data
 * @return    : success of failure
 */
uint32_t secflash_decrypt_sensitive_data(struct cmd_derivate_info *info, uint8_t *iv, uint8_t *data_buf,
    uint8_t *out_buf, uint32_t out_buf_length)
{
    uint8_t *decrypt_buf = NULL;
    uint16_t decrypt_iv[SECFLASH_IV_BYTE_LEN / sizeof(uint16_t)] = {0};
    uint8_t decrypt_key[SECFLASH_AES_KEY_BYTE_LEN] = {0};
    uint16_t context[SECFLASH_IV_BYTE_LEN / sizeof(uint16_t)] = {0};
    struct crypto_info value = {0};
    uint32_t ret;
    uint32_t i;
    uint32_t j;
    uint32_t status;

    if (!info || !iv || !data_buf || !out_buf)
        return SECFLASH_FAILURE | POINTER_NULL;

    /* data_length: info->block_count * SECFLASH_BLOCK_BYTE_LEN */
    if (out_buf_length < (info->block_count * SECFLASH_BLOCK_BYTE_LEN))
        return SECFLASH_FAILURE | INPUT_LEN_ERR;

    decrypt_buf = TEE_Malloc(info->block_count * SECFLASH_BLOCK_BYTE_LEN, 0);
    if (!decrypt_buf)
        return SECFLASH_FAILURE | MALLOC_ERR;

    value.iv = (uint8_t *)&decrypt_iv[0];
    value.iv_size = SECFLASH_BLOCK_BYTE_LEN;
    value.key = &decrypt_key[0];
    value.key_size = SECFLASH_AES_KEY_BYTE_LEN;
    value.crypto_algo = TEE_ALG_AES_CBC_NOPAD;
    value.operation_mode = TEE_MODE_DECRYPT;
    for (i = 0; i < info->block_count; i++) { /* AES-XTS decrypt every 16bytes block data */
        for (j = 0; j < SECFLASH_IV_BYTE_LEN / sizeof(uint16_t); j++) { /* count is 8 */
            decrypt_iv[j] = ((uint16_t)iv[j]) ^ ((uint16_t)(info->phy_block_index + i));
            context[j] = (uint16_t)(info->phy_block_index + i);
        }
        status = secflash_aes_cmac_wrapper((uint8_t *)&context[0], SECFLASH_AES_KEY_BYTE_LEN, decrypt_key);
        if (status != SECFLASH_SUCCESS)
            goto error_process;

        value.data_in = &data_buf[i * SECFLASH_BLOCK_BYTE_LEN];
        value.data_in_size = SECFLASH_BLOCK_BYTE_LEN;
        value.data_out = &decrypt_buf[i * SECFLASH_BLOCK_BYTE_LEN];
        status = secflash_crypto_aes(&value);
        if (status != SECFLASH_SUCCESS)
            goto error_process;
    }

    ret = memcpy_s(out_buf, out_buf_length, decrypt_buf, info->block_count * SECFLASH_BLOCK_BYTE_LEN);
    if (ret != EOK)
        status = SECFLASH_FAILURE | MEMCPY_ERR;

error_process:
    TEE_Free(decrypt_buf);
    decrypt_buf = NULL;
    (void)memset_s(&decrypt_key[0], SECFLASH_AES_KEY_BYTE_LEN, 0, SECFLASH_AES_KEY_BYTE_LEN);
    (void)memset_s((uint8_t *)&decrypt_iv[0], SECFLASH_IV_BYTE_LEN, 0, SECFLASH_IV_BYTE_LEN);
    return status;
}
