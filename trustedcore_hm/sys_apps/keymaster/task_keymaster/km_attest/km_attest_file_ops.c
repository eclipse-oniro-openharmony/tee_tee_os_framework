/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: keymaster attest file operation
 * Create: 2016-05-04
 */
#include "securec.h"
#include "km_defines.h"
#include "km_attest.h"
#include "km_common.h"
#include "crypto_wrapper.h"
static int32_t get_file_name_index(int alg, int32_t file_type)
{
    bool check = (alg == ALG_EC) && (file_type == FILE_TYPE_PRVKEY);
    if (check)
        return EC_PRIVKEY_INDEX;

    check = (alg == ALG_EC) && (file_type == FILE_TYPE_CERT);
    if (check)
        return EC_CERT_INDEX;

    check = (alg == ALG_RSA) && (file_type == FILE_TYPE_PRVKEY);
    if (check)
        return RSA_PRIVKEY_INDEX;

    check = (alg == ALG_RSA) && (file_type == FILE_TYPE_CERT);
    if (check)
        return RSA_CERT_INDEX;
    tloge("invalid alg:%d file type %d\n", alg, file_type);
    return -1;
}

static int32_t get_src_index(int32_t src)
{
    if (src == SRC_GOOGLE) {
        return 0;
    } else if (src == SRC_HUAWEI) {
        return 1;
    }
    tloge("src is invalid:[%d].\n", src);
    return -1;
}

static int32_t printf_file_name(keymaster_blob_t *out_name_blob, const char *file_name, const char *src_str,
                                int32_t file_type, int32_t cert_num)
{
    bool paramc_check = (out_name_blob == NULL || out_name_blob->data_addr == NULL || file_name == NULL ||
        src_str == NULL || out_name_blob->data_length < 1);
    if (paramc_check)
        return 0;
    int32_t rc;
    if (file_type == FILE_TYPE_CERT) {
        rc = snprintf_s((char *)(out_name_blob->data_addr), out_name_blob->data_length, out_name_blob->data_length - 1,
            "%s/%s_%d", src_str, file_name, cert_num);
        if (rc <= 0) {
            tloge("[error]snprintf_s failed, rc=%d, line:%d\n", rc, __LINE__);
            return AT_FILE_NAME_ERROR;
        }
    } else if (file_type == FILE_TYPE_PRVKEY) {
        rc = snprintf_s((char *)(out_name_blob->data_addr), out_name_blob->data_length, out_name_blob->data_length - 1,
            "%s/%s", src_str, file_name);
        if (rc <= 0) {
            tloge("[error]snprintf_s failed, rc=%d, line:%d\n", rc, __LINE__);
            return AT_FILE_NAME_ERROR;
        }
    } else {
        tloge("invalid file_type:%d\n", file_type);
        return AT_FILE_NAME_ERROR;
    }
    tlogd("get file name:%s---\n", (char *)(out_name_blob->data_addr));
    return 0;
}

int32_t get_file_name(keymaster_blob_t *out_name_blob, int32_t src, int32_t alg, int32_t file_type, int32_t cert_num)
{
    if (out_name_blob == NULL || out_name_blob->data_addr == NULL) {
        tloge("invalid out name!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    char *file_name_all[] = {"ec_prvkey", "ec_cert", "rsa_prvkey", "rsa_cert"};
    char *src_str_all[] = {"google", "huawei"};

    int32_t src_index = get_src_index(src);
    if (src_index == -1) {
        tloge("get src name error!\n");
        return AT_FILE_NAME_ERROR;
    }

    int32_t file_index = get_file_name_index(alg, file_type);
    if (file_index == -1) {
        tloge("get file name error!\n");
        return AT_FILE_NAME_ERROR;
    }
    return printf_file_name(out_name_blob, file_name_all[file_index], src_str_all[src_index], file_type, cert_num);
}

int32_t get_attest_key(int src, int32_t alg, void *prv_key)
{
    tlogd("get atest key begin\n");
    if (prv_key == NULL) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret;
    uint32_t prv_key_len;
    char file_name[FILE_NAME_LEN_MAX] = { 0 };
    file_operations_t *file_ops       = get_file_operation_info();
    keymaster_blob_t file_name_blob = { (uint8_t *)file_name, sizeof(file_name) };
    ret = get_file_name(&file_name_blob, src, alg, FILE_TYPE_PRVKEY, 0);
    if (ret != 0) {
        tloge("get attest key file error: ret =%d\n", ret);
        return ret;
    }

    /* read prv key file, ALG_EC or ALG_RSA */
    bool condition = (alg == ALG_EC) || (alg == ALG_RSA);
    if (!condition) {
        tloge("invalid algo:%d\n", alg);
        return TEE_ERROR_GENERIC;
    }
    prv_key_len = (alg == ALG_EC) ? sizeof(ecc_priv_key_t) : sizeof(rsa_priv_key_t);
    ret = file_ops->read(file_name, prv_key, prv_key_len);
    if (ret != (int)prv_key_len) {
        tloge("read attest key file error: ret=%d,file_name=%s\n", ret, file_name);
        if (ret < 0)
            return ret;
        return AT_FILE_SIZE_ERROR;
    }
    tlogd("get atest key success, attest key file size=%d\n", ret);
    return 0;
}

/* save identifiers name */
static const char g_file_name[] = "sec_storage/attestation/identifiers";

TEE_Result destroy_identifiers(void)
{
    file_operations_t *file_ops = get_file_operation_info();
    int ret = set_file_operation();
    if (ret != TEE_SUCCESS) {
        tloge("set_file_operation failed\n");
        return ret;
    }
    ret = file_ops->remove(g_file_name);
    if (ret != 0)
        tloge("remove failed, ret 0x%x\n", ret);
    tlogd("destroy_identifiers success\n");
    return TEE_SUCCESS;
}

identifiers_stored *read_identifiers(void)
{
    identifiers_stored *local = NULL;
    int size;
    int readsize;
    file_operations_t *file_ops = get_file_operation_info();
    if (set_file_operation() != TEE_SUCCESS) {
        tloge("set_file_operation failed\n");
        return NULL;
    }
    size = file_ops->filesize(g_file_name);
    if (size != sizeof(identifiers_stored)) {
        tloge("size %d is invalid\n", size);
        return NULL;
    }
    local = (identifiers_stored *)TEE_Malloc(size, 0);
    if (local == NULL) {
        tloge("malloc failed\n");
        return NULL;
    }
    readsize = file_ops->read(g_file_name, (uint8_t *)local, size);
    if (readsize != size) {
        tloge("read size %d is invalid\n", readsize);
        TEE_Free(local);
        local = NULL;
        return NULL;
    }
    return local;
}
TEE_Result verify_identifiers(const identifiers_stored *identifiers)
{
    if (identifiers == NULL) {
        tloge("the identifiers is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t size;
    file_operations_t *file_ops = get_file_operation_info();
    if (set_file_operation() != TEE_SUCCESS) {
        tloge("set_file_operation failed\n");
        return TEE_ERROR_GENERIC;
    }
    size = file_ops->filesize(g_file_name);
    if (size != sizeof(identifiers_stored)) {
        tloge("size %d is invalid\n", size);
        return TEE_ERROR_GENERIC;
    }
    identifiers_stored *local = (identifiers_stored *)TEE_Malloc(size, 0);
    if (local == NULL) {
        tloge("malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    int32_t ret = file_ops->read(g_file_name, (uint8_t *)local, size);
    if (ret != size) {
        tloge("read size %d is invalid\n", ret);
        TEE_Free(local);
        local = NULL;
        return TEE_ERROR_GENERIC;
    }
    ret = (int)TEE_MemCompare(local->hmac, identifiers->hmac, HMAC_SHA256_SIZE);
    if (ret != 0) {
        tloge("hmac compare failed");
        TEE_Free(local);
        local = NULL;
        return TEE_ERROR_GENERIC;
    }
    TEE_Free(local);
    local = NULL;
    tlogd("verify_identifiers success\n");
    return TEE_SUCCESS;
}

TEE_Result store_identifiers(const identifiers_stored *identifiers)
{
    if (identifiers == NULL) {
        tloge("the identifiers is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret;
    file_operations_t *file_ops = get_file_operation_info();
    if (set_file_operation() != TEE_SUCCESS) {
        tloge("set_file_operation failed\n");
        return TEE_ERROR_GENERIC;
    }
    ret = file_ops->write(g_file_name, (uint8_t *)identifiers, sizeof(identifiers_stored));
    if (ret != 0) {
        tloge("write primary file error:ret=%d, g_file_name=%s\n", ret, g_file_name);
        return TEE_ERROR_GENERIC;
    }
    tlogd("store_identifiers %s success\n", g_file_name);
    return TEE_SUCCESS;
}

static int32_t km_save_file(const char *file_name, uint8_t *buf, uint32_t len)
{
    tlogd("km_save_file begin\n");
    bool check = (file_name == NULL) || (buf == NULL) || (len == 0);
    if (check) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t ret;
    file_operations_t *file_ops = get_file_operation_info();

    /* write primary file */
    ret = file_ops->write(file_name, buf, len);
    if (ret) {
        tloge("write primary file error:ret=%d, file_name=%s\n", ret, file_name);
        return ret;
    }
    tlogd("saved file[%s] size=%d\n", file_name, file_ops->filesize(file_name));
    tlogd("km_save_file success\n");
    return ret;
}

static int32_t save_certs(const struct dev_key_t *dev_key, keymaster_blob_t *file_name_blob)
{
    int32_t ret;
    int32_t i;
    for (i = 0; i < (int)dev_key->chain.entry_count; i++) {
        /* save dev cert file */
        ret = get_file_name(file_name_blob, dev_key->src, dev_key->alg, FILE_TYPE_CERT, i);
        if (ret) {
            tloge("cert[%d]'s file name get error\n", i);
            return ret;
        }
        ret = km_save_file((const char *)(file_name_blob->data_addr), dev_key->chain.entries[i].data_addr,
            dev_key->chain.entries[i].data_length);
        if (ret) {
            tloge("save cert dev file error\n");
            return ret;
        }
    }
    return 0;
}

int32_t km_store_devkey(const struct dev_key_t *dev_key)
{
    tlogd("km_store_devkey begin\n");
    if (dev_key == NULL) {
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
    /* save prvkey file */
    ret = get_file_name(&file_name_blob, dev_key->src, dev_key->alg, FILE_TYPE_PRVKEY, 0);
    if (ret) {
        tloge("prkey's file name get error\n");
        return ret;
    }
    ret = km_save_file(file_name, dev_key->prv_key.data_addr, dev_key->prv_key.data_length);
    if (ret) {
        tloge("save prvkey file error\n");
        return ret;
    }
    /* save the certs */
    ret = save_certs(dev_key, &file_name_blob);
    if (ret)
        return ret;

    tlogd("km_store_devkey success\n");
    return ret;
}