/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2019. All rights reserved.
 * Description: keymaster tag params operation
 * Create: 2016-01-17
 */
#include "km_tag_operation.h"
#include "tee_mem_mgmt_api.h"
#include "tee_crypto_api.h"
#include "securec.h"
#include "tee_log.h"
#include "tee_ext_api.h"
#include "keymaster_defs.h"
#include "securec.h"
#include "km_env.h"
#include "crypto_wrapper.h"
#include "km_crypto_adaptor.h"
#include "km_crypto.h"
#include "pthread.h"
#include "sre_syscalls_ext.h"

#ifdef BORINGSSL_ENABLE
#include "openssl/nid.h"
#else
#include "openssl/obj_mac.h"
#endif
#undef UINT8_MAX
#undef UINT16_MAX
#undef INT32_MAX

#ifdef LOG_ON
#define PRINT_MAX_LEN (1024 * 5)
#define PRINT_ONE_LEN 2048
#define PRINT_ONE_LINE 16
#define FIX_ONE_PRINT 3
void mem_print(const char *head, const uint8_t *buf, uint32_t len)
{
    char p[PRINT_ONE_LEN] = {0};
    uint32_t i = 0;
    uint32_t j = 0;
    if (buf == NULL) {
        tloge("buffer is null");
        return;
    }
    if (len > PRINT_MAX_LEN) {
        tloge("len too large %u for print", len);
        len = PRINT_MAX_LEN;
    }
    tloge("%s,buffer len %u content:\n", head, len);
    while (i < len) {
        uint8_t c = buf[i];
        if (snprintf_s(p + j, PRINT_ONE_LEN - j, FIX_ONE_PRINT, " %02x", c) == -1) {
            tloge("memory dump fail %u", j);
            return;
        }
        j += FIX_ONE_PRINT;
        if ((i + 1) % PRINT_ONE_LINE == 0) {
            tloge("%s\n", p);
            j = 0;
            (void)memset_s(p, PRINT_ONE_LEN, 0, PRINT_ONE_LEN);
        }
        i++;
    }
    tloge("%s\n", p);
}
#else
void mem_print(const char *head, const uint8_t *buf, uint32_t len)
{
    (void)head;
    (void)buf;
    (void)len;
}
#endif
uint64_t byte_to_int64(const uint8_t *buf, uint32_t size)
{
    uint64_t value = 0;
    uint32_t i;
    if (buf == NULL) {
        tloge("the buf is null");
        return 0;
    }
    if (size > BYTES_INT64) {
        tloge("size %u greater than 8", size);
        return 0;
    }
    for (i = 0; i < size; i++)
        value |= ((uint64_t)buf[i]) << ((size - 1 - i) * BYTES_INT64);

    return value;
}

static bool check_is_repeat_tag_from_params(const keymaster_key_param_t *params, uint32_t params_len,
                                            keymaster_tag_t tag)
{
    uint32_t i;
    uint32_t find_times = 0;

    for (i = 0; i < params_len; i++) {
        if (tag == params[i].tag) {
            find_times++;
            if (find_times > 1)
                return true;
        }
    }
    return false;
}
typedef void (*set_tag_value_t)(keymaster_key_param_t *input_param, const void *value);
struct tag_type_func {
    keymaster_tag_type_t type;
    set_tag_value_t func;
};
static void set_bool_value(keymaster_key_param_t *input_param, const void *value)
{
    input_param->boolean = (*(bool *)(value));
}
static void set_enum_value(keymaster_key_param_t *input_param, const void *value)
{
    input_param->enumerated = (*(uint32_t *)(value));
}
static void set_uint_value(keymaster_key_param_t *input_param, const void *value)
{
    input_param->integer = (*(uint32_t *)(value));
}
static void set_long_value(keymaster_key_param_t *input_param, const void *value)
{
    input_param->long_integer = (*(uint64_t *)value);
}
static void set_date_value(keymaster_key_param_t *input_param, const void *value)
{
    input_param->date_time = (*(uint64_t *)value);
}

typedef void (*set_value_tag_t)(const keymaster_key_param_t *param, void *value);
struct type_param_func {
    keymaster_tag_type_t type;
    set_value_tag_t func;
};
static void set_value_enum(const keymaster_key_param_t *param, void *value)
{
    *(uint32_t *)value = param->enumerated;
}
static void set_value_bool(const keymaster_key_param_t *param, void *value)
{
    *(bool *)value = param->boolean;
}
static void set_value_uint(const keymaster_key_param_t *param, void *value)
{
    *(uint32_t *)value = param->integer;
}
static void set_value_ulong(const keymaster_key_param_t *param, void *value)
{
    *(uint64_t *)value = param->long_integer;
}
static void set_value_date(const keymaster_key_param_t *param, void *value)
{
    *(uint64_t *)value = param->date_time;
}

int32_t get_key_param_from_params(const keymaster_key_param_t *params, uint32_t params_len, uint8_t *extend_bufer_in,
    keymaster_tag_t tag, void *value)
{
    uint32_t i, j;
    bool condition = (params == NULL || value == NULL);
    if (condition) {
        tloge("null pointer\n");
        return 0;
    }
    struct type_param_func tag_func_list[] = {
        { KM_BOOL, set_value_bool }, { KM_ENUM, set_value_enum }, { KM_ENUM_REP, set_value_enum },
        { KM_UINT, set_value_uint }, { KM_UINT_REP, set_value_uint }, { KM_ULONG, set_value_ulong },
        { KM_ULONG_REP, set_value_ulong }, { KM_DATE, set_value_date }
    };

    for (i = 0; i < params_len; i++) {
        if (tag != params[i].tag)
            continue;
        keymaster_tag_type_t type = keymaster_tag_get_type(tag);
        for (j = 0; j < sizeof(tag_func_list) / sizeof(struct type_param_func); j++) {
            if (type == tag_func_list[j].type) {
                tag_func_list[j].func(&(params[i]), value);
                return 1;
            }
        }
        condition = ((keymaster_tag_get_type(tag) == KM_BIGNUM) || (keymaster_tag_get_type(tag) == KM_BYTES));
        if (condition) {
            if (extend_bufer_in == NULL) {
                tloge("extend_bufer_in is null\n");
                return 0;
            }
            keymaster_blob_t *key_blob_t = (keymaster_blob_t *)value;
            /* what store in blob.data is offset but not point addr,the offset get from data buffer */
            key_blob_t->data_addr = extend_bufer_in + params[i].blob.data_offset;
            key_blob_t->data_length = params[i].blob.data_length;
            return 1;
        }
    }
    return 0;
}

static int adapt_tag_type(keymaster_key_param_t *input_param, keymaster_tag_t tag, const void *value)
{
    keymaster_tag_type_t tag_type;
    struct tag_type_func tag_func_list[] = {
        { KM_BOOL, set_bool_value }, { KM_ENUM, set_enum_value }, { KM_ENUM_REP, set_enum_value },
        { KM_UINT, set_uint_value }, { KM_UINT_REP, set_uint_value }, { KM_ULONG, set_long_value },
        { KM_ULONG_REP, set_long_value }, { KM_DATE, set_date_value }
    };
    tag_type = keymaster_tag_get_type(tag);
    uint32_t i;
    for (i = 0; i < sizeof(tag_func_list) / sizeof(struct tag_type_func); i++) {
        if (tag_type == tag_func_list[i].type) {
            tag_func_list[i].func(input_param, value);
            return 1;
        }
    }
    bool condition = (tag_type == KM_BIGNUM || tag_type == KM_BYTES);
    if (condition)
        tloge("tag 0x%x parse error with valid type\n", tag);
    else
        tloge("tag 0x%x parse error with invalid type\n", tag);
    return 0;
}

int32_t is_key_param_suport(keymaster_tag_t tag, const void *value, const keymaster_key_param_set_t *param_keymaster)
{
    uint32_t i;
    int ret;
    keymaster_key_param_t input_param;
    input_param.tag = tag;
    if (param_keymaster == NULL) {
        tloge("param_keymaster is null");
        return 0;
    }
    if (value == NULL) {
        tloge("value is null");
        return 0;
    }

    ret = adapt_tag_type(&input_param, tag, value);
    if (ret != 1)
        return ret;
    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)param_keymaster +
                                        sizeof(param_keymaster->length));
    if (params_hw == NULL) {
        tloge("params_hw is null\n");
        return 0;
    }
    uint32_t hw_enforced_len = *(uint32_t *)param_keymaster;
    for (i = 0; i < hw_enforced_len; i++) {
        if (keymaster_param_compare(&params_hw[i], &input_param) != 0)
            continue;
        else
            return 1;
    }

    keymaster_key_param_t *params_sw =
        (keymaster_key_param_t *)((uint8_t *)param_keymaster + sizeof(param_keymaster->length) +
                                  (hw_enforced_len * sizeof(keymaster_key_param_t)) + sizeof(uint32_t));
    if (params_sw == NULL) {
        tloge("params_sw is null\n");
        return 0;
    }
    uint32_t sw_enforced_len = *(uint32_t *)((uint8_t *)param_keymaster + sizeof(uint32_t) +
        (hw_enforced_len * sizeof(keymaster_key_param_t)));
    for (i = 0; i < sw_enforced_len; i++)
        if (keymaster_param_compare(&params_sw[i], &input_param) != 0)
            continue;
        else
            return 1;
    tlogd("failed to find input_param.tag is 0x%x\n", input_param.tag);
    return 0;
}

/* valid: 0:get value, 1:judge value is valid in param_keymaster */
int32_t get_key_param(keymaster_tag_t tag, void *value, const keymaster_key_param_set_t *param_keymaster)
{
    bool condition = (param_keymaster == NULL || value == NULL);
    if (condition)
        return -1;
    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)param_keymaster +
                                        sizeof(param_keymaster->length));
    if (params_hw == NULL) {
        tloge("params_hw is null\n");
        return -1;
    }
    uint32_t hw_enforced_len = *(uint32_t *)param_keymaster;
    tlogd("hw_enforced_len is %u\n", hw_enforced_len);
    keymaster_key_param_t *params_sw =
        (keymaster_key_param_t *)((uint8_t *)param_keymaster + sizeof(param_keymaster->length) +
        (hw_enforced_len * sizeof(keymaster_key_param_t)) + sizeof(uint32_t));
    if (params_sw == NULL) {
        tloge("params_sw is null");
        return -1;
    }
    uint32_t sw_enforced_len =
        *(uint32_t *)((uint8_t *)params_hw + (hw_enforced_len * sizeof(keymaster_key_param_t)));
    uint8_t *extend_bufer_in =
        (uint8_t *)((uint8_t *)param_keymaster + sizeof(uint32_t) + (hw_enforced_len * sizeof(keymaster_key_param_t)) +
                    sizeof(uint32_t) + (sw_enforced_len * sizeof(keymaster_key_param_t)));
    condition = ((tag == KM_TAG_PADDING || tag == KM_TAG_DIGEST) &&
        (check_is_repeat_tag_from_params(params_hw, hw_enforced_len, tag) ||
        check_is_repeat_tag_from_params(params_sw, sw_enforced_len, tag)));
    if (condition) {
        tloge("repeat tag 0x%x", tag);
        return -1;
    }
    /* find tag in hw_enforced params */
    if (get_key_param_from_params(params_hw, hw_enforced_len, extend_bufer_in, tag, value) == 1)
        return 0;

    /* find tag in sw_enforced params */
    if (get_key_param_from_params(params_sw, sw_enforced_len, extend_bufer_in, tag, value) == 1)
        return 0;

    return -1;
}

#define ATTRIBUTE_COUNT_ONE 1ul
#define HMAC_MAX_KEY_SIZE_BITS 1024
TEE_ObjectHandle hmac_sha256_generate_keyobject(uint8_t *hmac_key)
{
    if (hmac_key == NULL) {
        tloge("hmac key is null.\n");
        return TEE_HANDLE_NULL;
    }
    TEE_Result ret;
    TEE_Attribute attrib = { 0 };
    TEE_ObjectHandle gen_key = TEE_HANDLE_NULL;

    ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, HMAC_MAX_KEY_SIZE_BITS, &gen_key);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute allocate transient object:0x%x\n", ret);
        return TEE_HANDLE_NULL;
    }
    TEE_InitRefAttribute(&attrib, TEE_ATTR_SECRET_VALUE, hmac_key, HMAC_SIZE);
    ret = TEE_PopulateTransientObject(gen_key, &attrib, ATTRIBUTE_COUNT_ONE);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute populate transient object:0x%x\n", ret);
        TEE_FreeTransientObject(gen_key);
        gen_key = TEE_HANDLE_NULL;
        return TEE_HANDLE_NULL;
    }
    return gen_key;
}

int32_t proc_keymaster_hmac(const uint8_t *src, uint32_t src_size, uint8_t *dst, uint8_t *key)
{
    errno_t rc;
    TEE_Result ret;
    int32_t ret_value = 0;
    size_t out_len = HMAC_SIZE;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    TEE_OperationHandle hmac_ops = TEE_HANDLE_NULL;
    key_object = hmac_sha256_generate_keyobject(key);
    if (key_object == TEE_HANDLE_NULL) {
        tloge("Err input KEY, generate key object failed\n");
        ret_value = -1;
        goto op_error;
    }
    ret = init_key_operation(&hmac_ops, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, HMAC_MAX_KEY_SIZE_BITS, &key_object);
    if (ret != TEE_SUCCESS) {
        tloge("alloc and init crypto operation failed, result=0x%x\n", ret);
        ret_value = -1;
        goto op_error;
    }
    TEE_MACInit(hmac_ops, NULL, 0);
    ret = TEE_MACComputeFinal(hmac_ops, (void *)src, (size_t)src_size, (void *)dst, &out_len);
    if (ret != 0) {
        tloge("TEE_MAC ComputeFinal failed, ret=0x%x\n", ret);
        ret_value = -1;
    }
op_error:
    TEE_FreeTransientObject(key_object);
    key_object = TEE_HANDLE_NULL;
    TEE_FreeOperation(hmac_ops);
    hmac_ops = TEE_HANDLE_NULL;
    rc = memset_s(key, HMAC_SIZE, 0, HMAC_SIZE);
    if (rc != EOK) {
        tloge("memset_s failed, rc 0x%x\n", rc);
        return -1;
    }
    return ret_value;
}

/*
 * gen_or_check:0 - generate HMAC
 *              1 - check original lock color
 *              2 - check adaptalbe lock color
 * adaptable:0 - needn't check adaptable color
 *           1 - need check adaptable color
 */
int32_t keymaster_hmac(const uint8_t *src, uint32_t src_size, uint8_t *dst, int32_t gen_or_check, int32_t *adaptable,
                       uint32_t version, const keymaster_blob_t *application_id)
{
    int ret;
    uint8_t key[HMAC_SIZE] = { 0 };

    ret = preproc_keymaster_hmac(gen_or_check, adaptable, version, application_id, key);
    if (ret != 0) {
        tloge("preproc_keymaster_hmac failed\n");
        return -1;
    }
    return proc_keymaster_hmac(src, src_size, dst, key);
}

keymaster_error_t rsa_indata_size_larger_modulus(uint32_t src_len, keymaster_padding_t padding,
                                                 keymaster_digest_t digest, uint32_t key_size)
{
    keymaster_error_t ret = KM_ERROR_OK;
    uint32_t modulus_size = (key_size + BITS_UP_BYTE_BASE) / BITS_ONE_BYTE;
    uint32_t digest_size = 0;
    if (hash_mode_to_size_bits(digest, &digest_size) != KM_ERROR_OK) {
        tloge("get hash size bits failed\n");
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }
    digest_size = eight_align_up(digest_size) / BITS_ONE_BYTE;
    tlogd("tcm key_size is %u, modulus_size is %u, digest_size is %u\n", key_size, modulus_size, digest_size);
    switch (padding) {
    case KM_PAD_NONE:
        if (src_len > modulus_size)
            ret = KM_ERROR_INVALID_ARGUMENT;
        break;
    case KM_PAD_RSA_OAEP:
        if (src_len > min_oaep_padding_outsize(modulus_size, digest_size))
            ret = KM_ERROR_INVALID_INPUT_LENGTH;
        break;
    case KM_PAD_RSA_PSS:
        break;
    case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
    case KM_PAD_RSA_PKCS1_1_5_SIGN:
        if (src_len > (modulus_size - RSA_PKCS1_PADDING_SIZE))
            ret = KM_ERROR_INVALID_INPUT_LENGTH;
        break;
    case KM_PAD_PKCS7:
        break;
    default:
        ret = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        break;
    }
    return ret;
}

int32_t get_saltlen_for_cc(uint32_t module_len, uint32_t digest_mode, uint16_t *salt_len)
{
    uint32_t h_len = 0;
    keymaster_uint2uint digest_to_cc_rsa_hash[] = {
        { KM_DIGEST_MD5,       16 },
        { KM_DIGEST_SHA1,      20 },
        { KM_DIGEST_SHA_2_224, 28 },
        { KM_DIGEST_SHA_2_256, 32 },
        { KM_DIGEST_SHA_2_384, 48 },
        { KM_DIGEST_SHA_2_512, 64 }
    };
    if (salt_len == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    if (look_up_table(digest_to_cc_rsa_hash, sizeof(digest_to_cc_rsa_hash) / sizeof(keymaster_uint2uint),
        digest_mode, &h_len) != TEE_SUCCESS) {
        tloge("invalied digest_mode %u\n", digest_mode);
        return -1;
    }

    /*
     *  _DX_RSA_Sign @param[in] SaltLen - The Length of the Salt buffer (relevant for PKCS#1 Ver 2.1 only)
     *  Typical lengths are 0 and hLen (20 for SHA1)
     *  The maximum length allowed is NSize - hLen - 2.
     */
    if (module_len < min_module_len_cc(h_len))
        return -1;

    if ((module_len - min_module_len_cc(h_len)) > h_len)
        *salt_len = (uint16_t)h_len;
    else
        *salt_len = (uint16_t)(module_len - min_module_len_cc(h_len));
    return 0;
}

int32_t length_check(int len, int in_size)
{
    if (len < 0) {
        tloge("len is error %d", len);
        return -1;
    }
    if (in_size < len) {
        tloge("len is error %d in is %d", len, in_size);
        return -1;
    }
    return 0;
}

static int km_compare_by_bytes(const keymaster_key_param_t *a, const keymaster_key_param_t *b)
{
    /* Handle the empty cases. */
    int ret_val;
    bool check = (a->blob.data_length != 0 && b->blob.data_length == 0);
    if (check)
        return -1;
    check = (a->blob.data_length == 0 && b->blob.data_length == 0);
    if (check)
        return 0;
    check = (a->blob.data_length == 0 && b->blob.data_length > 0);
    if (check)
        return 1;
    ret_val = memcmp((uint8_t *)a + a->blob.data_offset, (uint8_t *)b + b->blob.data_offset,
                     (a->blob.data_length < b->blob.data_length) ? a->blob.data_length : b->blob.data_length);
    if (ret_val != 0) {
        return ret_val;
    } else if (a->blob.data_length != b->blob.data_length) {
        /* Equal up to the common length; longer one is larger. */
        if (a->blob.data_length < b->blob.data_length)
            return -1;
        if (a->blob.data_length > b->blob.data_length)
            return 1;
    }
    return 0;
}

static int km_compare_by_tag(const keymaster_key_param_t *a, const keymaster_key_param_t *b)
{
    switch (keymaster_tag_get_type(a->tag)) {
    case KM_INVALID:
    case KM_BOOL:
        return 0;
    case KM_ENUM:
    case KM_ENUM_REP:
        return km_tag_compare(a->enumerated, b->enumerated);
    case KM_UINT:
    case KM_UINT_REP:
        return km_tag_compare(a->integer, b->integer);
    case KM_ULONG:
    case KM_ULONG_REP:
        return km_tag_compare(a->long_integer, b->long_integer);
    case KM_DATE:
        return km_tag_compare(a->date_time, b->date_time);
    case KM_BIGNUM:
    case KM_BYTES:
        return km_compare_by_bytes(a, b);
    default:
        return 0;
    }
}

int keymaster_param_compare(const keymaster_key_param_t *a, const keymaster_key_param_t *b)
{
    if (a == NULL || b == NULL)
        return -1;
    int ret_val = km_tag_compare(a->tag, b->tag);
    if (ret_val != 0)
        return ret_val;
    return km_compare_by_tag(a, b);
}

keymaster_error_t pack_input_data_to_pkcs1_format(uint32_t input_data_len, uint32_t size_bytes,
                                                  const uint8_t *input_data, uint8_t *temp_buf)
{
    uint32_t j;
    errno_t rc;

    if ((temp_buf == NULL) || (input_data == NULL && input_data_len != 0)) {
        tloge("the temp_buf or input_data is null");
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    uint8_t *temp_buf2 = temp_buf;

    /* padding to PKCS1 format, then pass to CRYS_RSA_PRIM_Decrypt */
    *(temp_buf2++) = 0;
    *(temp_buf2++) = 1; /* Private Key BT (Block Type) */
    /* pad out with 0xff data */
    j = size_bytes - HEAD_INCLUDE_FF_LEN - input_data_len;
    if (j > size_bytes) {
        tloge("length is error");
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }
    rc = memset_s(temp_buf2, j, 0xff, j);
    if (rc != EOK) {
        tloge("memset_s failed, rc 0x%x\n", rc);
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    temp_buf2 += j;
    *(temp_buf2++) = 0;
    if (input_data_len > 0) {
        rc = memcpy_s(temp_buf2, size_bytes - (temp_buf2 - temp_buf), input_data, (unsigned int)input_data_len);
        if (rc != EOK) {
            tloge("memcpy_s failed, rc 0x%x\n", rc);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    }
    return KM_ERROR_OK;
}
