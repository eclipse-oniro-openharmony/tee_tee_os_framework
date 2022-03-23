/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: keymaster tag operation header
 * Create: 2016-05-04
 */

#ifndef __KM_TAG_OPERATION_H
#define __KM_TAG_OPERATION_H
#include <dlist.h>
#include "tee_internal_api.h"

#include "keymaster_defs.h"
#include "km_types.h"
#include "crypto_wrapper.h"
#include "km_keynode.h"
#include "keyblob.h"

enum lock_state {
    LSTATE_LOCKED,
    LSTATE_UNLOCKED,
    LSTATE_MAX
};

enum lock_color {
    LOCK_GREEN,
    LOCK_YELLOW,
    LOCK_ORANGE,
    LOCK_RED,
    LOCK_COLOR_MAX
};

typedef struct km_root_of_trust {
    keymaster_blob_t verified_boot_key;
    enum lock_state device_locked;
    enum lock_color verified_boot_state;
} km_root_of_trust_t;

struct verify_boot_mem_struct {
    char lock_state[COLOR_LOCK_STATE_SIZE];
    char lock_color[COLOR_LOCK_COLOR_SIZE];
    char pub_key[PUBLIC_KEY_SIZE];
    /* operating system version and security patch level; for
     * version "A.B.C" and patch level "Y-M-D":
     * rule1: ver = A << 14 | B << 7 | C         (7 bits for each of A, B, C)
     * rule2: lvl = ((Y - 2000) & 127) << 4 | M  (7 bits for Y, 4 bits for M)
     * rule3: os_version = ver << 11 | lvl
     */
    uint32_t os_version_info;
};
#ifdef MTK_BOOT_INFO
#define PUBLIC_KEY_HASH_SIZE 32
#define RESERVED_SIZE        4
struct verify_boot_mem_struct_mtk {
    unsigned char pubk_hash[PUBLIC_KEY_HASH_SIZE];
    int device_lock_state; /* lock:0x0, unlock:0x1 */
    int verify_boot_state; /* green:0x0, orange:0x1, yellow:0x2, red: 0x3 */
    uint32_t os_version;
    unsigned char reserved[RESERVED_SIZE];
};
#endif

struct verify_boot_info_struct {
    enum lock_state lstate;
    enum lock_color color;
    char pub_key[PUBLIC_KEY_SIZE];
    uint32_t os_version;         /* system osversion */
    uint32_t patch_level;        /* system patchlevel */
    uint32_t boot_patch_level;   /* boot patchlevel */
    uint32_t vendor_patch_level; /* vendor patchlevel */
};

void mem_print(const char *head, const uint8_t *buf, uint32_t len);

uint64_t byte_to_int64(const uint8_t *buf, uint32_t size);
int32_t keymaster_hmac(const uint8_t *src, uint32_t src_size, uint8_t *dst, int32_t gen_or_check, int32_t *adaptable,
                       uint32_t version, const keymaster_blob_t *application_id);
int32_t get_key_param(keymaster_tag_t tag, void *value, const keymaster_key_param_set_t *param_keymaster);

TEE_Result rsa_get_pub(const keymaster_blob_t *keymaterial_blob, rsa_pub_key_t *sw_pubkey_rsa, uint32_t version,
    const struct kb_crypto_factors *factors, uint32_t key_size);

int32_t get_key_param_from_params(const keymaster_key_param_t *params, uint32_t params_len, uint8_t *extend_bufer_in,
    keymaster_tag_t tag, void *value);
int32_t is_key_param_suport(keymaster_tag_t tag, const void *value, const keymaster_key_param_set_t *param_keymaster);

keymaster_error_t rsa_encrypt_decrypt(key_auth *key_node, keymaster_purpose_t purpose, uint8_t *src_data,
                                      uint32_t src_len, uint8_t *dest_data, uint32_t *dest_len, int force);
keymaster_error_t add_data_update(key_auth *key_node, uint8_t *in_data, uint32_t in_size);

int extract_final_input(const keymaster_blob_t *in_data, keymaster_blob_t *input, keymaster_blob_t *signature);
keymaster_error_t rsa_indata_size_larger_modulus(uint32_t src_len, keymaster_padding_t padding,
                                                 keymaster_digest_t digest, uint32_t key_size);

int32_t get_saltlen_for_cc(uint32_t module_len, uint32_t digest_mode, uint16_t *salt_len);
int32_t length_check(int len, int in_size);
int32_t get_real_hash_len(keymaster_digest_t digest, uint32_t *hash_size);

int32_t proc_keymaster_hmac(const uint8_t *src, uint32_t src_size, uint8_t *dst, uint8_t *key);

#define MAX_PKCS1_RSA_SIGN_VERIFY_DISPATCH_ITEM 6

#define MAX_PSS_RSA_SIGN_VERIFY_DISPATCH_ITEM 5

void get_application_id(keymaster_blob_t *application_id, const keymaster_key_param_set_t *params_enforced);
int keymaster_param_compare(const keymaster_key_param_t *a, const keymaster_key_param_t *b);


TEE_Result process_algorithm_key(TEE_Param *params, keymaster_algorithm_t algorithm, uint32_t key_size,
                                 const keymaster_key_param_set_t *params_hw_enforced);

TEE_Result get_cur_version(const keymaster_key_param_set_t *param, keymaster_algorithm_t alg, uint32_t *version);

TEE_ObjectHandle hmac_sha256_generate_keyobject(uint8_t *hmac_key);
keymaster_error_t pack_input_data_to_pkcs1_format(uint32_t input_data_len, uint32_t size_bytes,
                                                  const uint8_t *input_data, uint8_t *temp_buf);

#endif
