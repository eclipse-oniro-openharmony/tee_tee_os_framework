/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster attest key provision
 * Create: 2020-10-04
 */

#include "securec.h"
#include "km_attest_factory.h"
#include "km_attest.h"
#include "tee_ext_api.h"
#include "km_common.h"
#include "km_types.h"
#include "openssl/sha.h"
#include "crypto_wrapper.h"
#include "km_crypto.h"
#include "km_attest_factory.h"

static int32_t check_attlvnode_common(struct dev_key_t *dev_key, struct verify_info *v_info, int32_t value)
{
    if (dev_key != NULL) {
        dev_key->alg = value;
        tlogd("dev_key->alg=%d---\n", dev_key->alg);
    } else if (v_info != NULL) {
        v_info->alg = value;
        tlogd("v_info->alg=%d---\n", v_info->alg);
    } else {
        tloge("dev_key and v_info both null\n");
        return AT_TLV_DECODE_ERR;
    }
    return AT_SUCCESS;
}
static int32_t check_attlvnode_alg(const int32_t *tlv_node_len, const int32_t *dev_key_len, uint8_t **p,
    struct dev_key_t *dev_key, struct verify_info *v_info)
{
    bool check = (*tlv_node_len != (int)sizeof(uint32_t)) || (*dev_key_len < (int)sizeof(uint32_t));
    if (check) {
        tloge("invalid ALG tlv node\n");
        return AT_TLV_DECODE_ERR;
    }
    int32_t value = get_next_int4(p);
    check = (value == ALG_EC) || (value == ALG_RSA);
    if (!check) {
        tloge("invalid ALG:[%d]\n", value);
        return AT_TLV_DECODE_ERR;
    }
    return check_attlvnode_common(dev_key, v_info, value);
}

static int32_t check_attlvnode_devid(const int32_t *tlv_node_len, const int32_t *dev_key_len, uint8_t **p,
    struct dev_key_t *dev_key, struct verify_info *v_info)
{
    bool check = (*tlv_node_len > 1) && (*dev_key_len >= *tlv_node_len);
    if (!check) {
        tloge("invalid DevId tlv node\n");
        return AT_TLV_DECODE_ERR;
    }
    if (dev_key != NULL) {
        dev_key->dev_id = (char *)*p;
        tlogd("dev_key->dev_id=%s---\n", dev_key->dev_id);
    } else if (v_info != NULL) {
        v_info->dev_id = (char *)*p;
        tlogd("v_info->dev_id=%s---\n", v_info->dev_id);
    } else {
        tloge("dev_key and v_info both null\n");
        return AT_TLV_DECODE_ERR;
    }
    *p += (*tlv_node_len);
    return AT_SUCCESS;
}

static int32_t check_attlvnode_src(const int32_t *tlv_node_len, const int32_t *dev_key_len, uint8_t **p,
    struct dev_key_t *dev_key, struct verify_info *v_info)
{
    bool check = (*tlv_node_len != (int)sizeof(uint32_t)) || (*dev_key_len < (int)sizeof(uint32_t));
    if (check) {
        tloge("invalid SRC tlv node\n");
        return AT_TLV_DECODE_ERR;
    }
    int32_t value = get_next_int4(p);
    check = (value == SRC_GOOGLE) || (value == SRC_HUAWEI);
    if (!check) {
        tloge("invalid SRC:[%d]\n", value);
        return AT_TLV_DECODE_ERR;
    }
    if (dev_key != NULL) {
        dev_key->src = value;
        tlogd("dev_key->src=%d---\n", dev_key->src);
    } else if (v_info != NULL) {
        v_info->src = value;
        tlogd("v_info->src=%d---\n", v_info->src);
    } else {
        tloge("dev_key and v_info both null\n");
        return AT_TLV_DECODE_ERR;
    }
    return AT_SUCCESS;
}

static int32_t check_attlvnode_prvkey(const int32_t *tlv_node_len, const int32_t *dev_key_len, uint8_t **p,
    struct dev_key_t *dev_key)
{
    bool check = (*tlv_node_len > 0) && dev_key && (*dev_key_len >= *tlv_node_len);
    if (!check) {
        tloge("invalid prvkey tlv node\n");
        return AT_TLV_DECODE_ERR;
    }

    uint8_t *prv_key = NULL;
    int32_t ret;
    /* suppose dev_key->alg is EC or RSA, no other type */
    check = (dev_key->alg == ALG_EC) || (dev_key->alg == ALG_RSA);
    if (!check) {
        tloge("invalid key alg:%d\n", dev_key->alg);
        return AT_TLV_DECODE_ERR;
    }

    uint32_t prv_key_len = (dev_key->alg == ALG_EC) ? sizeof(ecc_priv_key_t) : sizeof(rsa_priv_key_t);
    prv_key = (uint8_t *)TEE_Malloc(prv_key_len, TEE_MALLOC_FILL_ZERO);
    if (prv_key == NULL) {
        tloge("TEE_Malloc rsa_priv_key_t failed\n");
        return AT_MEM_ERR;
    }
    ret = (dev_key->alg == ALG_EC) ? ecc_import_priv((ecc_priv_key_t *)prv_key, *p, (uint32_t)*tlv_node_len) :
                                     rsa_import_priv((rsa_priv_key_t *)prv_key, *p, (uint32_t)*tlv_node_len);
    if (ret < 0) {
        tloge("import priv(alg:%d) is error\n", dev_key->alg);
        if (memset_s(prv_key, prv_key_len, 0, prv_key_len))
            tloge("prv_key memset_s failed\n");
        TEE_Free(prv_key);
        prv_key = NULL;
        return AT_TLV_DECODE_ERR;
    }

    dev_key->prv_key.data_length = prv_key_len;
    if (dev_key->prv_key.data_addr != NULL) {
        if (memset_s(dev_key->prv_key.data_addr, dev_key->prv_key.data_length, 0, dev_key->prv_key.data_length) != EOK)
            tloge("dev_key->prv_key.data_addr memset_s failed\n");
        TEE_Free(dev_key->prv_key.data_addr);
        dev_key->prv_key.data_addr = NULL;
    }
    dev_key->prv_key.data_addr = prv_key;
    tlogd("dev_key->prv_key->data_length=%u---\n", dev_key->prv_key.data_length);

    *p += *tlv_node_len;
    return AT_SUCCESS;
}

static int32_t check_attlvnode_certs_alloc(int32_t *dev_key_len, struct dev_key_t *dev_key, int32_t value)
{
    if ((UINT32_MAX / sizeof(keymaster_blob_t)) < (uint32_t)value) {
        tloge("invalid dev_key->chain.entry_count %d\n", value);
        dev_key->chain.entry_count = 0;
        dev_key->chain.entries = NULL;
        return AT_TLV_DECODE_ERR;
    }
    dev_key->chain.entries = (keymaster_blob_t *)TEE_Malloc(sizeof(keymaster_blob_t) * value, 0);
    if (dev_key->chain.entries == NULL) {
        tloge("TEE_Malloc chain entries failed\n");
        dev_key->chain.entry_count = 0;
        dev_key->chain.entries = NULL;
        return AT_MEM_ERR;
    }
    tlogd("dev_key->chain->entry_count=%u---\n", dev_key->chain.entry_count);
    *dev_key_len -= (int)sizeof(int);
    return AT_SUCCESS;
}

static int32_t check_attlvnode_certs(int32_t *dev_key_len, uint8_t **p, struct dev_key_t *dev_key)
{
    if (*dev_key_len < (int)sizeof(int)) {
        tloge("invalid certs tlv node\n");
        return AT_TLV_DECODE_ERR;
    }
    int32_t value = get_next_int4(p);
    bool check = (value > 0) && dev_key;
    if (!check) {
        tloge("invalid certs count:[%d]", value);
        return AT_TLV_DECODE_ERR;
    }
    dev_key->chain.entry_count = (uint32_t)value;
    if (dev_key->chain.entries != NULL) {
        TEE_Free(dev_key->chain.entries);
        dev_key->chain.entries = NULL;
    }
    return check_attlvnode_certs_alloc(dev_key_len, dev_key, value);
}

static int32_t check_attlvnode_cert_entry(int32_t *cert_count, const int32_t *tlv_node_len, const int32_t *dev_key_len,
    uint8_t **p, struct dev_key_t *dev_key)
{
    bool check = (*tlv_node_len > 0) && dev_key && (*cert_count < (int32_t)dev_key->chain.entry_count) &&
                 (*dev_key_len >= *tlv_node_len);
    if (check) {
        dev_key->chain.entries[*cert_count].data_addr = *p;
        dev_key->chain.entries[*cert_count].data_length = (uint32_t)(*tlv_node_len);
        tlogd("cert_count=%d and cert length=%u---\n", *cert_count, dev_key->chain.entries[*cert_count].data_length);
        (*cert_count)++;
    } else {
        tloge("invalid cert entry tlv node\n");
        return AT_TLV_DECODE_ERR;
    }
    *p += *tlv_node_len;
    return AT_SUCCESS;
}

static int32_t check_attlvnode_hash(const int32_t *tlv_node_len, const int32_t *dev_key_len, uint8_t **p,
    struct dev_key_t *dev_key)
{
    errno_t rc;
    bool check = (*tlv_node_len == SHA256_LENGTH) && dev_key && (*dev_key_len >= *tlv_node_len);
    if (check) {
        rc = memcpy_s(dev_key->hash, SHA256_LENGTH, *p, SHA256_LENGTH);
        if (rc != EOK) {
            tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
            return AT_TLV_DECODE_ERR;
        }
    } else {
        tloge("invalid hash tlv node\n");
        return AT_TLV_DECODE_ERR;
    }
    *p += *tlv_node_len;
    return AT_SUCCESS;
}

static int32_t check_attlvnode_cert_hash(const int32_t *tlv_node_len, const int32_t *dev_key_len, uint8_t **p,
    struct verify_info *v_info)
{
    errno_t rc;
    bool check = (*tlv_node_len == SHA256_LENGTH) && v_info && (*dev_key_len >= *tlv_node_len);
    if (check) {
        rc = memcpy_s(v_info->cert_hash, sizeof(v_info->cert_hash), *p, SHA256_LENGTH);
        if (rc != EOK) {
            tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
            return AT_TLV_DECODE_ERR;
        }
    } else {
        tloge("invalid cert hash tlv node\n");
        return AT_TLV_DECODE_ERR;
    }
    *p += *tlv_node_len;
    return AT_SUCCESS;
}

static int32_t do_decode_tlv(int32_t tlv_node_type, const int32_t *tlv_node_len, int32_t *dev_key_len, uint8_t **p,
    struct verify_info *v_info, struct dev_key_t *dev_key, uint32_t *cert_count)
{
    int32_t ret_check = 0;
    switch (tlv_node_type) {
    case ATTLVNODE_NONE:
        tloge("empty node\n");
        return AT_TLV_DECODE_ERR;
        /* decode alg node */
    case ATTLVNODE_ALG:
        ret_check = check_attlvnode_alg(tlv_node_len, dev_key_len, p, dev_key, v_info);
        break;
        /* decode DevId node */
    case ATTLVNODE_DEVID:
        ret_check = check_attlvnode_devid(tlv_node_len, dev_key_len, p, dev_key, v_info);
        break;
    case ATTLVNODE_SRC:
        ret_check = check_attlvnode_src(tlv_node_len, dev_key_len, p, dev_key, v_info);
        break;
    case ATTLVNODE_PRVKEY:
        ret_check = check_attlvnode_prvkey(tlv_node_len, dev_key_len, p, dev_key);
        break;
    case ATTLVNODE_CERTS:
        ret_check = check_attlvnode_certs(dev_key_len, p, dev_key);
        break;
    case ATTLVNODE_CERT_ENTRY:
        ret_check = check_attlvnode_cert_entry((int32_t *)cert_count, tlv_node_len, dev_key_len, p, dev_key);
        break;
    case ATTLVNODE_HASH:
        ret_check = check_attlvnode_hash(tlv_node_len, dev_key_len, p, dev_key);
        break;
    case ATTLVNODE_VB_INFO:
        break;
    case ATTLVNODE_CERT_HASH:
        ret_check = check_attlvnode_cert_hash(tlv_node_len, dev_key_len, p, v_info);
        break;
    default:
        tloge("unkown tlv node type:[%d]\n", tlv_node_type);
        ret_check = AT_TLV_DECODE_ERR;
    }
    return ret_check;
}

static int32_t set_format_type(uint8_t **p, int32_t in_type, void *format, struct dev_key_t **dev_key,
    struct verify_info **v_info)
{
    bool check = (p == NULL || format == NULL || dev_key == NULL || v_info == NULL);
    if (check) {
        tloge("bad parameters\n");
        return AT_TLV_BUF_INVALID;
    }
    int32_t dev_key_type = get_next_int4(p);
    check = (dev_key_type != in_type || (dev_key_type != ATTLVNODE_DEVKEY && dev_key_type != ATTLVNODE_VB_INFO));
    if (check) {
        tloge("in_type is invalid\n");
        return AT_TLV_BUF_INVALID;
    }
    if (dev_key_type == ATTLVNODE_DEVKEY)
        *dev_key = (struct dev_key_t *)format;
    if (dev_key_type == ATTLVNODE_VB_INFO)
        *v_info = (struct verify_info *)format;
    return 0;
}

int32_t decode_tlv(uint8_t *buf, uint32_t len, void *format, int32_t in_type)
{
    tlogd("\ndecode_tlv begin-----\n");
    struct dev_key_t *dev_key = NULL;
    struct verify_info *v_info = NULL;
    /* check params */
    bool condition = ((buf == NULL) || (len < sizeof(uint32_t) * KM_NUM_TWO) || (format == NULL));
    if (condition) {
        tloge("tlv buffer is null or content empty\n");
        return AT_TLV_BUF_INVALID;
    }
    uint8_t *p = buf;
    /* decode tlv header */
    if (set_format_type(&p, in_type, format, &dev_key, &v_info) != 0) {
        tloge("decode format type failed\n");
        return AT_TLV_BUF_INVALID;
    }
    int32_t dev_key_len = get_next_int4(&p);
    if ((uint32_t)dev_key_len + sizeof(uint32_t) * KM_NUM_TWO != len) {
        tloge("tlv dev_key_len is invalid:[%d]\n", dev_key_len);
        return AT_TLV_BUF_INVALID;
    }
    uint32_t cert_count = 0;
    /* decode tlv nodes */
    while (dev_key_len >= (int32_t)(sizeof(uint32_t) * KM_NUM_TWO)) {
        int32_t tlv_node_type = get_next_int4(&p);
        int32_t tlv_node_len = get_next_int4(&p);
        dev_key_len -= sizeof(uint32_t) * KM_NUM_TWO;
        tlogd("decode node type=%d, len=%d----\n", tlv_node_type, tlv_node_len);
        int32_t ret_check = do_decode_tlv(tlv_node_type, &tlv_node_len, &dev_key_len, &p, v_info, dev_key, &cert_count);
        if (ret_check != 0)
            return ret_check;

        /* sub len */
        condition = ((tlv_node_type != ATTLVNODE_CERTS) && (tlv_node_type != ATTLVNODE_VB_INFO) &&
            dev_key_len >= tlv_node_len);
        if (condition)
            dev_key_len -= tlv_node_len;
    }
    tlogd("decode tlv success\n");
    return 0;
}

static int32_t sign_with_devkey(const keymaster_blob_t *in, keymaster_blob_t *out, const struct dev_key_t *dev_key)
{
    tlogd("sign_with_devkey begin\n");
    bool check = (in == NULL || in->data_addr == NULL || out == NULL || out->data_addr == NULL || dev_key == NULL);
    if (check) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check = (in->data_length == 0) || (out->data_length == 0);
    if (check) {
        tloge("invalid input/output length!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t ret;
    uint32_t sig_out_len = out->data_length;
    uint8_t hash_buf[SHA256_LENGTH] = { 0 };
    /* hash */
    uint8_t *result = SHA256(in->data_addr, in->data_length, hash_buf);
    if (result == NULL) {
        tloge("TEE_EXT_HASH failed");
        return AT_SIGN_HASH_ERR;
    }
    /* sign */
    ret   = do_sign_func(&sig_out_len, hash_buf, out->data_addr, dev_key);
    check = (ret < 0) || (out->data_length < (uint32_t)ret);
    if (check) {
        tloge("sign failed, ret %d\n", ret);
        return AT_SIGN_ERR;
    }
    out->data_length = (uint32_t)ret;
    tlogd("sign_with_devkey success out len=%u\n", out->data_length);
    return TEE_SUCCESS;
}

static int32_t km_read_compare_file(const file_operations_t *file_ops, const char *file_name,
    uint32_t read_buf_len, const uint8_t *hash)
{
    if (read_buf_len <= 0 || read_buf_len > FILE_SIZE_MAX) {
        tloge("read_buf_len is invaild\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *read_buf = (uint8_t *)TEE_Malloc(read_buf_len, 0);
    if (read_buf == NULL) {
        tloge("read buf malloc failed\n");
        return AT_MEM_ERR;
    }

    int32_t ret = file_ops->read(file_name, read_buf, read_buf_len);
    if (ret != (int)read_buf_len) {
        tloge("read primary file error: ret=%d and file_name=%s\n", ret, file_name);
        if (ret >= 0)
            ret = AT_FILE_SIZE_ERROR;
        TEE_Free(read_buf);
        return ret;
    }
    tlogd("read file[%s] size=%d\n", file_name, ret);

    /* hash compare */
    if (hash_compare(read_buf, read_buf_len, hash)) {
        tloge("hash compare file is not same\n");
        TEE_Free(read_buf);
        return AT_COMPARE_FILE_ERROR;
    }

    TEE_Free(read_buf);
    tlogd("km_check_file_entry success\n");
    return 0;
}

static int32_t km_check_file(const char *file_name, const uint8_t *hash)
{
    if ((file_name == NULL) || (hash == NULL)) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t read_buf_len;
    file_operations_t *file_ops = get_file_operation_info();
    /* read primary file */
    int32_t ret = file_ops->filesize(file_name);
    if (ret < 0) {
        tloge("get file size error: ret=%d and file_name=%s\n", ret, file_name);
        return ret;
    }
    if (ret == 0) {
        tloge("file size is zero: file_name=%s\n", file_name);
        return AT_FILE_SIZE_ERROR;
    }

    read_buf_len = (uint32_t)ret;
    return  km_read_compare_file(file_ops, file_name, read_buf_len, hash);
}

static int32_t km_do_verify(const struct verify_info *v_info)
{
    tlogd("km_do_verify begin\n");
    if (v_info == NULL) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* set file ops */
    int32_t ret = set_file_operation();
    if (ret != TEE_SUCCESS) {
        tloge("set_file_operation failed\n");
        return ret;
    }
    char file_name[FILE_NAME_LEN_MAX] = { 0 };
    keymaster_blob_t file_name_blob = { (uint8_t *)file_name, sizeof(file_name) };
    /* check dev cert file */
    ret = get_file_name(&file_name_blob, v_info->src, v_info->alg, FILE_TYPE_CERT, 0);
    if (ret != 0) {
        tloge("verfiy: get cert[0] file name error\n");
        return ret;
    }
    ret = km_check_file(file_name, v_info->cert_hash);
    if (ret != 0) {
        tloge("check file error: file_name=%s\n", file_name);
        return ret;
    }

    tlogd("km_do_verify success\n");
    return 0;
}

TEE_Result get_iv(uint8_t *iv_at, uint32_t kb_len, const uint8_t *kb_buf)
{
    errno_t rc;
    if (kb_len <= CBC_IV_LENGTH) {
        tloge("input param is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rc = memcpy_s(iv_at, CBC_IV_LENGTH, kb_buf, CBC_IV_LENGTH);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return (TEE_Result)AT_MEM_ERR;
    }
    return TEE_SUCCESS;
}

static void free_decrypt_buf(uint8_t **decrypt_buf, uint32_t en_len)
{
    if (*decrypt_buf != NULL) {
        if (memset_s(*decrypt_buf, en_len, 0, en_len) != EOK)
            tloge("decrypt_buf memset_s failed\n");
        TEE_Free(*decrypt_buf);
        *decrypt_buf = NULL;
    }
}

static void free_dev_key(struct dev_key_t **dev_key)
{
    if (*dev_key != NULL) {
        km_free_cert_chain(&(*dev_key)->chain);

        if ((*dev_key)->prv_key.data_addr != NULL) {
            if (memset_s((*dev_key)->prv_key.data_addr, (*dev_key)->prv_key.data_length, 0,
                         (*dev_key)->prv_key.data_length) != EOK)
                tloge("dev_key->prv_key.data_addr memset_s failed\n");
            TEE_Free((*dev_key)->prv_key.data_addr);
            (*dev_key)->prv_key.data_addr = NULL;
        }

        TEE_Free(*dev_key);
        *dev_key = NULL;
    }
}

void free_all(struct dev_key_t **dev_key, uint8_t **decrypt_buf, uint32_t en_len)
{
    if (dev_key != NULL)
        free_dev_key(dev_key);
    if (decrypt_buf != NULL)
        free_decrypt_buf(decrypt_buf, en_len);
    tlogd("km_store_kb end-----------\n");
}

static TEE_Result km_store_kb_check(const keymaster_blob_t *decrytp_buf, const struct dev_key_t *dev_key,
    uint32_t text_signed_len, uint32_t chain_len)
{
    if (text_signed_len != SIG_MAX_LEN) {
        tloge("invliad output param:sign buffer, len=%u\n", text_signed_len);
        return (TEE_Result)AT_SIGN_ERR;
    }
    if (chain_len != CHAIN_MAX_LEN) {
        tloge("invliad output param:out chain buffer, len=%u\n", chain_len);
        return (TEE_Result)AT_CHAIN_OUT_ERR;
    }
    int32_t ret;
    uint32_t hash_node_len = SHA256_LENGTH + (sizeof(uint32_t) * KM_NUM_TWO);
    if (decrytp_buf->data_length < hash_node_len) {
        tloge("decrypt buf len invalid:%u\n", decrytp_buf->data_length);
        ret = AT_HASH_CHECK_ERR;
        return (TEE_Result)ret;
    }
    ret = hash_compare(decrytp_buf->data_addr, decrytp_buf->data_length - hash_node_len, dev_key->hash);
    if (ret != 0) {
        tloge("error in hash_compare\n");
        return (TEE_Result)ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result devkey_check_store_and_sign(keymaster_blob_t *decrypt_buf, struct dev_key_t *dev_key,
    keymaster_blob_t *text_signed, const keymaster_blob_t *text_to_sign, uint32_t chain_len)
{
    TEE_Result ret = km_store_kb_check(decrypt_buf, dev_key, text_signed->data_length, chain_len);
    if (ret != TEE_SUCCESS)
        return ret;
    /* store files */
    ret = (TEE_Result)km_store_devkey(dev_key);
    if (ret != TEE_SUCCESS) {
        tloge("error in km_store_devkey\n");
        return ret;
    }
    /* sign digest */
    ret = (TEE_Result)sign_with_devkey(text_to_sign, text_signed, dev_key);
    if (ret != TEE_SUCCESS)
        tloge("error in sign_with_devkey\n");
    return ret;
}
TEE_Result check_and_store_keybox(keymaster_blob_t *decrypt_buf, struct dev_key_t *dev_key,
    keymaster_blob_t *text_signed, const keymaster_blob_t *text_to_sign, TEE_Param *params,
    uint32_t chain_len, uint8_t *chain)
{
    TEE_Result ret = devkey_check_store_and_sign(decrypt_buf, dev_key, text_signed, text_to_sign, chain_len);
    if (ret != TEE_SUCCESS) {
        tloge("dev key check store and sign failed\n");
        return ret;
    }
    params[PARAM_NBR_TWO].memref.size = text_signed->data_length;
    /* format output chain entry_count||cert_len||cert_context||cert_len||cert_context */
    uint32_t i;
    uint8_t *tmp = chain;
    if (memcpy_s(tmp, sizeof(uint32_t), (void *)&(dev_key->chain.entry_count), sizeof(uint32_t)) != EOK) {
        tloge("memcpy failed\n");
        return (TEE_Result)AT_CHAIN_OUT_ERR;
    }
    tmp += sizeof(uint32_t);
    uint32_t chain_len_out = sizeof(uint32_t);
    for (i = 0; i < dev_key->chain.entry_count; i++) {
        uint32_t next_entry_len = sizeof(uint32_t) + dev_key->chain.entries[i].data_length;
        if ((UINT32_MAX - chain_len_out) < next_entry_len || ((chain_len_out + next_entry_len) > chain_len)) {
            tloge("format chain out error: buf len is invalid[%u]\n", chain_len);
            return (TEE_Result)AT_CHAIN_OUT_ERR;
        }
        if (memcpy_s(tmp, chain_len - chain_len_out, (void *)&(dev_key->chain.entries[i].data_length),
                     sizeof(uint32_t)) != EOK) {
            tloge("memcpy entries %u data length failed", i);
            return (TEE_Result)AT_CHAIN_OUT_ERR;
        }
        tmp += sizeof(uint32_t);
        chain_len_out += sizeof(uint32_t);
        if (memcpy_s(tmp, chain_len - chain_len_out, dev_key->chain.entries[i].data_addr,
                     dev_key->chain.entries[i].data_length) != EOK) {
            tloge("memcpy entries %u data failed", i);
            return (TEE_Result)AT_CHAIN_OUT_ERR;
        }
        tmp += dev_key->chain.entries[i].data_length;
        chain_len_out += dev_key->chain.entries[i].data_length;
    }
    params[PARAM_NBR_THREE].memref.size = chain_len_out;
    return TEE_SUCCESS;
}

TEE_Result compare_files_and_sign_digest(const struct verify_info *v_info, uint32_t *text_signed_len,
    uint8_t *text_to_sign, uint8_t *text_signed, uint32_t text_to_sign_len)
{
    TEE_Result ret;
    ret = (TEE_Result)km_do_verify(v_info);
    if (ret != TEE_SUCCESS) {
        tloge("error in km_do_verify\n");
        return (TEE_Result)ret;
    }

    /* sign digest */
    if (*text_signed_len != SIG_MAX_LEN) {
        tloge("invliad output param:sign buffer, len=%u\n", *text_signed_len);
        return (TEE_Result)AT_SIGN_ERR;
    }
    keymaster_blob_t in, out;
    in.data_addr = text_to_sign;
    in.data_length = text_to_sign_len;
    out.data_addr = text_signed;
    out.data_length = *text_signed_len;
    ret = (TEE_Result)sign_with_attest_key(&in, &out, v_info->src, v_info->alg);
    if (ret != TEE_SUCCESS) {
        tloge("error in sign_with_attest_key\n");
        return (TEE_Result)ret;
    }
    *text_signed_len = out.data_length;
    tlogd("text_signed_len=%u\n", *text_signed_len);
    return TEE_SUCCESS;
}
