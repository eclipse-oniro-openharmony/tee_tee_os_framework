/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM kms api function head
 * Author: chenyao
 * Create: 2020-01-08
 */
#ifndef _HSM_KMS_API_H_
#define _HSM_KMS_API_H_

#include "hsm_public.h"

typedef struct {
    uint32_t            alg_id;
    CRYPTO_KEY_ELEMENT  symkey;
    uint8_t             *symkey_auth;
    uint32_t            symkey_authsize;
    uint8_t             *symkey_protectmsg;
} HSM_GENERATE_SYMKEY_INFO;

typedef struct {
    uint32_t            alg_id;
    CRYPTO_KEY_ELEMENT  prikey;
    CRYPTO_KEY_ELEMENT  pubkey;
    uint8_t             *key_auth;
    uint32_t            key_authsize;
    uint8_t             *prikey_protectmsg;
    uint8_t             *pubkey_protectmsg;
} HSM_GENERATE_ASYMKEY_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            salt_size;
    uint32_t            irt_num;
    uint8_t             *salt;
    CRYPTO_KEY_ELEMENT  c_key;
    uint8_t             *key_auth;
    uint32_t            key_authsize;
    uint8_t             *key_protectmsg;
} HSM_DERIVE_HUK_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            salt_size;
    uint32_t            irt_num;
    uint8_t             *salt;
    CRYPTO_KEY_ELEMENT  source_key;
    uint8_t             *source_key_auth;
    uint32_t            source_key_authsize;
    uint8_t             *source_key_protectmsg;
    CRYPTO_KEY_ELEMENT  target_key;
    uint8_t             *target_key_auth;
    uint32_t            target_key_authsize;
    uint8_t             *target_key_protectmsg;
} HSM_DERIVE_KEY_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            salt_size;
    uint32_t            irt_num;
    uint8_t             *salt;
    CRYPTO_KEY_ELEMENT  import_key;
    uint8_t             *import_key_auth;
    uint32_t            import_key_authsize;
    uint8_t             *import_key_info;
    uint8_t             *import_key_protectmsg;
} HSM_IMPORT_KEY_INFO;

typedef struct {
    uint32_t            alg_id;
    CRYPTO_KEY_ELEMENT  exchange_pubkey;
    uint8_t             *exchange_pubkey_auth;
    uint32_t            exchange_pubkey_authsize;
    uint8_t             *exchange_pubkey_protectmsg;
    uint8_t             *generate_pubkey;
    uint32_t            generate_pubkey_len;
    uint8_t             *generate_key_domain;
} HSM_EXCHANGE_PUBKEY_INFO;

typedef struct {
    uint32_t            alg_id;
    CRYPTO_KEY_ELEMENT  exchange_prikey;
    uint8_t             *exchange_prikey_auth;
    uint32_t            exchange_prikey_authsize;
    uint8_t             *exchange_prikey_protectmsg;
    uint8_t             *exchange_pubkey;
    uint32_t             exchange_pubkey_len;
    CRYPTO_KEY_ELEMENT  exchange_key;
    uint8_t             *exchange_key_auth;
    uint32_t            exchange_key_authsize;
    uint8_t             *exchange_key_protectmsg;
    uint8_t             *agree_key_domain;
    uint32_t            domain_size;
} HSM_EXCHANGE_KEY_INFO;

typedef struct {
    uint32_t            alg_id;
    CRYPTO_KEY_ELEMENT  prokey;
    uint8_t             *prokey_auth;
    uint32_t            prokey_authsize;
    uint8_t             *prokey_protectmsg;
} HSM_UPDATE_PROKEY_INFO;

typedef struct {
    uint8_t             *past_key_auth;
    uint32_t            past_key_authsize;
    uint8_t             *key_protectmsg;
    uint8_t             *new_key_auth;
    uint32_t            new_key_authsize;
} HSM_UPDATE_KEYAUTH_INFO;

typedef struct {
    uint8_t             *delete_key_auth;
    uint32_t            delete_key_authsize;
    uint8_t             *delete_key_protectmsg;
} HSM_DELETE_KEY_INFO;

typedef struct {
    uint32_t            alg_id;
    uint32_t            salt_size;
    uint32_t            irt_num;
    uint8_t             *salt;
    CRYPTO_KEY_ELEMENT  export_key;
    uint8_t             *export_key_auth;
    uint32_t            export_key_authsize;
    uint8_t             *export_key_protectmsg;
    uint8_t             *export_key_info;
} HSM_EXPORT_KEY_INFO;

typedef struct {
    uint32_t            *state;
    uint8_t             *append_data;
} HSM_BBOX_INFO;

TEE_Result TEE_HSM_GenSymeticKey(uint32_t dev_id, HSM_GENERATE_SYMKEY_INFO *generate_symkey_info);
TEE_Result TEE_HSM_GenAsymeticKey(uint32_t dev_id, HSM_GENERATE_ASYMKEY_INFO *generate_asymkey_info);
TEE_Result TEE_HSM_DeriveHuk(uint32_t dev_id, HSM_DERIVE_HUK_INFO *derive_huk_info);
TEE_Result TEE_HSM_DeriveKey(uint32_t dev_id, HSM_DERIVE_KEY_INFO *derive_key_info);
TEE_Result TEE_HSM_ImportKey(uint32_t dev_id, HSM_IMPORT_KEY_INFO *import_key_info);
TEE_Result TEE_HSM_ExchangePubKey(uint32_t dev_id, HSM_EXCHANGE_PUBKEY_INFO *exchange_pubkey);
TEE_Result TEE_HSM_ExchangeAgreeKey(uint32_t dev_id, HSM_EXCHANGE_KEY_INFO *exchange_agree_key);
TEE_Result TEE_HSM_UpdateProtectMsg(uint32_t dev_id, HSM_UPDATE_PROKEY_INFO *update_prokey_info);
TEE_Result TEE_HSM_UpdateAuth(uint32_t dev_id, HSM_UPDATE_KEYAUTH_INFO *update_keyauth_info);
TEE_Result TEE_HSM_DeleteKey(uint32_t dev_id, HSM_DELETE_KEY_INFO *delete_key_info);
TEE_Result TEE_HSM_ExportKey(uint32_t dev_id, HSM_EXPORT_KEY_INFO *export_key_info);
TEE_Result TEE_HSM_Bbox(uint32_t dev_id, HSM_BBOX_INFO *hsm_bbox_info, uint64_t tv_sec, uint64_t tv_usec);
TEE_Result TEE_HSM_notify_prereset(uint32_t dev_id);

#endif
