/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: permission handle config
 * Author: TianJianliang tianjianliang@huawei.com
 * Create: 2016-04-01
 */
#include "handle_config.h"
#include "handle_cert_storage_io.h"
#include <string.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include <crypto_wrapper.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include <timer_export.h>
#include "config_tlv_parser.h"
#include "handle_crl_cert.h"
#include "handle_ta_ctrl_list.h"
#include "tee_crypto_hal.h"

#define ISSUER_MAX_SIZE   256
#define CERT_ARRAY_SIZE   1024
#define DECIMAL_UNIT_SIZE 10
#define DATE_TAIL_INDEX   12
#define CMP_YEAR_ACCURACY 100
#define ECC_SIGNATURE_LEN 72

static uint32_t g_ca_type;

static conf_cert_t g_conf_cert_type;

struct cert_subjects {
    uint8_t cn[SN_MAX_SIZE];
    uint32_t cn_size;
    uint8_t ou[SN_MAX_SIZE];
    uint32_t ou_size;
};

TEE_Result ta_run_authorization_check(const TEE_UUID *uuid, const ta_property_t *manifest,
                                      uint16_t target_version, bool mem_page_align)
{
    TEE_Result ret;
    struct config_info config;

    (void)memset_s(&config, sizeof(config), 0, sizeof(config));
    bool is_invalid = (uuid == NULL || manifest == NULL);
    bool is_valid_device = true;
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = perm_srv_check_ta_deactivated(uuid, target_version);
    if (ret != TEE_SUCCESS) {
        tloge("The TA version %u is not allowed\n", target_version);
        return TEE_ERROR_GENERIC;
    }

    if (get_config_by_uuid(uuid, &config) != TEE_SUCCESS) {
        tloge("Failed to get config by uuid\n");
        return TEE_ERROR_GENERIC;
    }
#ifdef DYN_IMPORT_CERT
    if (config.manifest_info.sys_verify_ta)
        is_valid_device = config.control_info.debug_info.valid_device;
#else
    is_valid_device = config.control_info.debug_info.valid_device;
#endif
    is_invalid = ((manifest->heap_size <= config.manifest_info.heap_size) &&
                  (manifest->stack_size <= config.manifest_info.stack_size) &&
                  (bool)manifest->instance_keep_alive == config.manifest_info.instance_keep_alive &&
                  (bool)manifest->multi_command == config.manifest_info.multi_command &&
                  (bool)manifest->multi_session == config.manifest_info.multi_session &&
                  (bool)manifest->single_instance == config.manifest_info.single_instance &&
                  is_valid_device && mem_page_align == config.manifest_info.mem_page_align);
    if (is_invalid) {
        return TEE_SUCCESS;
    } else {
        tloge("heap size 0x%x : 0x%x\n", manifest->heap_size, config.manifest_info.heap_size);
        tloge("stack size 0x%x : 0x%x\n", manifest->stack_size, config.manifest_info.stack_size);
        tloge("keep alive 0x%x : 0x%x\n", manifest->instance_keep_alive, config.manifest_info.instance_keep_alive);
        tloge("multi command 0x%x : 0x%x\n", manifest->multi_command, config.manifest_info.multi_command);
        tloge("multi session 0x%x : 0x%x\n", manifest->multi_session, config.manifest_info.multi_session);
        tloge("single instance 0x%x : 0x%x\n", manifest->single_instance, config.manifest_info.single_instance);
        tloge("is valid device 0x%x\n", is_valid_device);
        tloge("mem page align 0x%x : 0x%x\n", mem_page_align, config.manifest_info.mem_page_align);
    }

    tloge("ta run authorization check manifest compare error\n");

    return TEE_ERROR_GENERIC;
}

static TEE_Result tee_secure_img_params_check(const uint8_t *cert, const uint8_t *parent_key)
{
    bool is_invalid = (cert == NULL || parent_key == NULL);
    if (is_invalid) {
        tloge("cert or parent is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

#ifndef CONFIG_OH_LOAD_KEY
static TEE_Result asn1_bytes_to_tee_time(const uint8_t *asn1_time, size_t asn1_buff_size, TEE_Date_Time *tm)
{
    (void)asn1_buff_size;
    /* asn1_time is encoded in  format "YYMMDDHHMMSSZ" */
    if (asn1_time[DATE_TAIL_INDEX] != 'Z')
        return TEE_ERROR_BAD_PARAMETERS;

    tm->year    = (uint32_t)ASN1_TO_INT(asn1_time[0]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[1]);
    tm->month   = (uint32_t)ASN1_TO_INT(asn1_time[2]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[3]);
    tm->day     = (uint32_t)ASN1_TO_INT(asn1_time[4]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[5]);
    tm->hour    = (uint32_t)ASN1_TO_INT(asn1_time[6]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[7]);
    tm->min     = (uint32_t)ASN1_TO_INT(asn1_time[8]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[9]);
    tm->seconds = (uint32_t)ASN1_TO_INT(asn1_time[10]) * DECIMAL_UNIT_SIZE + ASN1_TO_INT(asn1_time[11]);

    return TEE_SUCCESS;
}

static int32_t value_cmp(int32_t value1, int32_t value2)
{
    if (value1 > value2)
        return 1;

    if (value1 < value2)
        return -1;

    return 0;
}

static inline TEE_Result result_value_check(int32_t result)
{
    return result > 0 ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static TEE_Result tee_secure_img_cert_time_cmp(const TEE_Date_Time *time1, const TEE_Date_Time *time2)
{
    int32_t result;

    result = value_cmp(time1->year, time2->year);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->month, time2->month);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->day, time2->day);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->hour, time2->hour);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->min, time2->min);
    if (result != 0)
        return result_value_check(result);

    result = value_cmp(time1->seconds, time2->seconds);
    if (result != 0)
        return result_value_check(result);

    return TEE_ERROR_GENERIC;
}

#ifdef DYN_IMPORT_CERT
#define MAX_MOUNTH 12
static TEE_Result tee_secure_img_cert_expiration_note(const TEE_Date_Time *time1, const TEE_Date_Time *time2)
{
    /* time1 must be greater than timer2 */
    if (time1->year - time2->year > 1) {
        return TEE_SUCCESS; /* cert expiration time is greater than one year */
    } else if (time1->year - time2->year == 1) {
        if (time1->month == 1 && time2->month == MAX_MOUNTH) {
            if (time1->day <= time2->day)
                return TEE_ERROR_GENERIC;
        }
    } else {
        /* time1 year data equals time2 year data  */
        if (time1->month == time2->month) {
            return TEE_ERROR_GENERIC;
        } else if (time1->month - time2->month == 1) {
            if (time1->day <= time2->day)
                return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}
#endif
#endif

static TEE_Result cert_expiration_date_check(const validity_period_t *valid_date)
{
#ifdef CONFIG_OH_LOAD_KEY
    (void)valid_date;
#else
    TEE_Date_Time current = { 0 };
    TEE_Date_Time start   = { 0 };
    TEE_Date_Time end     = { 0 };
    TEE_Result ret;

    ret = asn1_bytes_to_tee_time(valid_date->start, sizeof(valid_date->start), &start);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get expiration start time from cert");
        return TEE_ERROR_GENERIC;
    }

    ret = asn1_bytes_to_tee_time(valid_date->end, sizeof(valid_date->end), &end);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get expiration end time from cert");
        return TEE_ERROR_GENERIC;
    }

    get_sys_date_time((tee_date_time_kernel *)&current);
    /* compare last two numbers of year */
    current.year = current.year % CMP_YEAR_ACCURACY;

    ret = tee_secure_img_cert_time_cmp(&current, &start);
    if (ret != TEE_SUCCESS) {
        tloge("cert expiration start date check failed");
        return ret;
    }

    ret = tee_secure_img_cert_time_cmp(&end, &current);
    if (ret != TEE_SUCCESS) {
        tloge("cert expiration end date check failed");
        return ret;
    }
#ifdef DYN_IMPORT_CERT
    ret = tee_secure_img_cert_expiration_note(&end, &current);
    if (ret != TEE_SUCCESS)
        tlogi("cert is about to expire next month"); /* just remind the user cert that the cert is about to expire */
#endif
#endif
    return TEE_SUCCESS;
}

TEE_Result cert_expiration_check(const uint8_t *cert, size_t cert_size)
{
    int32_t ret;
    validity_period_t valid_date = { { 0 }, { 0 } };

    /* Get validate date from the certificate */
    ret = get_validity_from_cert(&valid_date, (uint8_t *)cert, cert_size);
    if (ret < 0) {
        tloge("Failed to get valid date from certificate, errno: %d!\n", ret);
        return TEE_ERROR_GENERIC;
    }

    return cert_expiration_date_check(&valid_date);
}

TEE_Result tee_secure_img_check_cert_validation(const uint8_t *cert, size_t cert_size, const uint8_t *parent_key,
                                                uint32_t parent_key_len)
{
    int32_t ret;
    uint8_t sn[SN_MAX_SIZE] = { 0 };
    uint8_t issuer[ISSUER_MAX_SIZE] = { 0 };
    int32_t sn_size;
    int32_t issuer_size;
    bool revoked = false;
    TEE_Result result;

    result = tee_secure_img_params_check(cert, parent_key);
    if (result != TEE_SUCCESS)
        return result;

    /* Verify the certificate is signed by our CA center */
    ret = x509_cert_validate((uint8_t *)cert, cert_size, (void *)parent_key, parent_key_len);
    if (ret <= 0) {
        tloge("Failed to validate certificate, errno: %d\n", ret);
        return TEE_ERROR_GENERIC;
    }

    result = cert_expiration_check(cert, cert_size);
    if (result != TEE_SUCCESS) {
        tloge("cert is expired");
        return result;
    }

    /* Get issuer of the certificate */
    issuer_size = get_issuer_from_cert(issuer, sizeof(issuer), (uint8_t *)cert, cert_size);
    if (issuer_size < 0) {
        tloge("Failed to get issuer from certificate: %d\n", issuer_size);
        return TEE_ERROR_GENERIC;
    }

    /* Get serial number of the certificate */
    sn_size = get_serial_number_from_cert(sn, sizeof(sn), (uint8_t *)cert, cert_size);
    if (sn_size < 0) {
        tloge("Failed to get serial number from certificate: %d\n", sn_size);
        return TEE_ERROR_GENERIC;
    }

    /* Check whether the certificate is revoked */
    result = perm_srv_check_cert_revoked(sn, sn_size, issuer, issuer_size, &revoked);
    if (result != TEE_SUCCESS || revoked == true) {
        tloge("Failed to pass cert crl check\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_secure_img_parse_cert(rsa_pub_key_t *public_key, struct secure_img_data *data, uint8_t *ou,
                                     uint32_t *ou_size)
{
    int32_t ret;
    uint8_t buff[CERT_ARRAY_SIZE] = { 0 };
    int32_t len;
    bool is_invalid = (data == NULL || data->cert == NULL || public_key == NULL || data->cn == NULL || ou == NULL ||
                       ou_size == NULL || data->cn_size == 0 || *ou_size == 0);
    if (is_invalid) {
        tloge("params is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Get cn from the certificate */
    len = get_subject_CN(data->cn, data->cn_size, (uint8_t *)(data->cert), data->cert_size);
    if (len < 0) {
        tloge("Failed to get CN from certificate: %d\n", len);
        return TEE_ERROR_GENERIC;
    }

    data->cn_size = (uint32_t)len;

    /* Get OU from the certificate */
    len = get_subject_OU(ou, *ou_size, (uint8_t *)(data->cert), data->cert_size);
    if (len < 0) {
        tloge("Failed to validate certificate, length: %d\n", len);
        return TEE_ERROR_GENERIC;
    }
    *ou_size = (uint32_t)len;

    /* Parse the certificate to get the public key */
    len = get_subject_public_key_new(buff, sizeof(buff), (uint8_t *)(data->cert), data->cert_size);
    if (len < 0) {
        tloge("Failed to get subject public key from cert\n");
        return TEE_ERROR_GENERIC;
    }

    ret = import_pub_from_sp(public_key, buff, len);
    (void)memset_s(buff, sizeof(buff), 0, sizeof(buff));

    if (ret < 0) {
        tloge("Failed to get public key from subject public key\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result tee_secure_img_conf_cert_cn_check(const uint8_t *cn, size_t cn_size)
{
    const char *config_cn = get_config_cert_cn();
    bool check = (cn == NULL || cn_size > SN_MAX_SIZE);

    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    check = (config_cn != NULL && (strlen(config_cn) == cn_size && TEE_MemCompare(cn, config_cn, cn_size) == 0));
    if (check)
        return TEE_SUCCESS;

    tloge("size 0x%x, %s\n", cn_size, cn);
    return TEE_ERROR_GENERIC;
}

static TEE_Result oh_conf_cert_cn_check(const uint8_t *cn, size_t cn_size)
{
    const char *config_cn = get_oh_config_cert_cn();
    bool check = (cn == NULL || cn_size > SN_MAX_SIZE);

    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    check = (config_cn != NULL && strstr((const char *)cn, config_cn) != NULL);
    if (check)
        return TEE_SUCCESS;

    return TEE_ERROR_GENERIC;
}

static TEE_Result tee_secure_img_conf_cert_ou_check(const uint8_t *ou, size_t ou_size)
{
    const char *config_ou_prod = get_config_cert_ou_prod();
    bool check = (ou == NULL || ou_size > SN_MAX_SIZE);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    check = (config_ou_prod != NULL &&
             (ou_size == strlen(config_ou_prod) && TEE_MemCompare(ou, config_ou_prod, ou_size) == 0));
    if (check) {
        tlogd("TA certificate type: %s\n", "Production");
        return TEE_SUCCESS;
    }

    tloge("size: 0x%x, %s\n", ou_size, ou);
    return TEE_ERROR_GENERIC;
}

static TEE_Result oh_conf_cert_ou_check(const uint8_t *ou, size_t ou_size, conf_cert_t *cert_type)
{
    const char *config_ou_prod = get_oh_config_ou_prod();
    const char *config_ou_dev = get_oh_config_ou_dev();

    bool is_invalid = (ou == NULL || cert_type == NULL || ou_size > SN_MAX_SIZE);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    is_invalid = (config_ou_prod != NULL && strstr((const char *)ou, config_ou_prod) != NULL);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Production");
        *cert_type = CONF_RELEASE_CERT;
        return TEE_SUCCESS;
    }

    is_invalid = (config_ou_dev != NULL && strstr((const char *)ou, config_ou_dev) != NULL);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Development");
        *cert_type = CONF_DEBUG_CERT;
        return TEE_SUCCESS;
    }

    tloge("size: 0x%x, %s\n", ou_size, ou);
    return TEE_ERROR_GENERIC;
}

static TEE_Result tee_secure_img_ta_cert_ou_check(const uint8_t *ou, size_t ou_size, ta_cert_t *cert_type)
{
    const char *config_ou_prod = get_config_cert_ou_prod();
    const char *config_ou_dev = get_config_cert_ou_dev();

    bool is_invalid = (ou == NULL || cert_type == NULL || ou_size > SN_MAX_SIZE);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    is_invalid = (config_ou_prod != NULL &&
                  (ou_size == strlen(config_ou_prod) && TEE_MemCompare(ou, config_ou_prod, ou_size) == 0));
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Production");
        *cert_type = TA_RELEASE_CERT;
        return TEE_SUCCESS;
    }

    is_invalid = (config_ou_dev != NULL &&
                  (ou_size == strlen(config_ou_dev) && TEE_MemCompare(ou, config_ou_dev, ou_size) == 0));
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Development");
        *cert_type = TA_DEBUG_CERT;
        return TEE_SUCCESS;
    }

    tloge("size: 0x%x, %s\n", ou_size, ou);
    return TEE_ERROR_GENERIC;
}

static TEE_Result oh_ta_cert_ou_check(const uint8_t *ou, size_t ou_size, ta_cert_t *cert_type)
{
    const char *config_ou_prod = get_oh_config_ou_prod();
    const char *config_ou_dev = get_oh_config_ou_dev();

    bool is_invalid = (ou == NULL || cert_type == NULL || ou_size > SN_MAX_SIZE);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    is_invalid = (config_ou_prod != NULL && strstr((const char *)ou, config_ou_prod) != NULL &&
                  g_conf_cert_type == CONF_RELEASE_CERT);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Production");
        *cert_type = TA_RELEASE_CERT;
        return TEE_SUCCESS;
    }

    is_invalid = (config_ou_dev != NULL && strstr((const char *)ou, config_ou_dev) != NULL &&
                  g_conf_cert_type == CONF_DEBUG_CERT);
    if (is_invalid) {
        tlogd("TA certificate type: %s\n", "Development");
        *cert_type = TA_DEBUG_CERT;
        return TEE_SUCCESS;
    }

    tloge("size: 0x%x, %s\n", ou_size, ou);
    return TEE_ERROR_GENERIC;
}

static TEE_Result tee_secure_img_ta_cn_check(const uint8_t *cn_buff, uint32_t cn_size, const TEE_UUID *uuid,
                                             const uint8_t *service_name, uint32_t service_name_len)
{
    uint8_t buff[TA_CERT_MAX_CN_INFO_LEN] = { 0 };
    errno_t ret;

    bool is_invalid = (cn_buff == NULL || uuid == NULL || service_name == NULL || (cn_size > TA_CERT_MAX_CN_INFO_LEN) ||
                       (service_name_len > TA_CERT_MAX_CN_INFO_LEN - (UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE)));
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cn_size != service_name_len + UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE) {
        tloge("manifest name len 0x%x\n", service_name_len);
        tloge("invalid CN size in TA cert 0x%x\n", cn_size);
        return TEE_ERROR_GENERIC;
    }

    if (convert_uuid_to_str(uuid, (char *)buff, sizeof(buff)) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    buff[UUID_STR_LEN] = '_';
    ret = memcpy_s(&buff[UUID_STR_LEN + TA_CERT_CN_UNDERLINE_SIZE],
                   sizeof(buff) - UUID_STR_LEN - TA_CERT_CN_UNDERLINE_SIZE, service_name, service_name_len);
    if (ret != EOK)
        return TEE_ERROR_GENERIC;

    if (TEE_MemCompare(buff, cn_buff, cn_size) != 0) {
        tloge("CN content is mismatch with uuid or service name in manifest\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_secure_img_calc_hash(const uint8_t *hash_body, size_t hash_body_size, uint8_t *hash_result,
                                    size_t hash_result_size, uint32_t alg)
{
    TEE_Result tee_ret;
    TEE_OperationHandle crypto_ops = NULL;
    int32_t per_op_len; /* TEE_ALG_SHA256 */

    bool is_invalid =
        (hash_body == NULL || hash_result == NULL || hash_body_size == 0 || hash_result_size < SHA256_LEN);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    /*
     * Calculate the hash value of configure package
     * sha1 with DX driver
     */
    tee_ret = TEE_AllocateOperation(&crypto_ops, alg, TEE_MODE_DIGEST, 0);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;

    tee_ret = TEE_SetCryptoFlag(crypto_ops, SOFT_CRYPTO);
    if (tee_ret != TEE_SUCCESS) {
        tloge("set soft engine failed ret = 0x%x", tee_ret);
        TEE_FreeOperation(crypto_ops);
        return tee_ret;
    }

    while (hash_body_size > 0) {
        per_op_len = (hash_body_size > HASH_UPDATA_LEN ? HASH_UPDATA_LEN : hash_body_size);
        if (TEE_DigestUpdate(crypto_ops, hash_body, per_op_len) != TEE_SUCCESS) {
            TEE_FreeOperation(crypto_ops);
            crypto_ops = NULL;
            tloge("Failed to call\n");
            return TEE_ERROR_GENERIC;
        }

        hash_body_size -= per_op_len;
        hash_body += per_op_len;
    }

    tee_ret = TEE_DigestDoFinal(crypto_ops, NULL, 0, hash_result, &hash_result_size);
    TEE_FreeOperation(crypto_ops);

    return tee_ret;
}

static TEE_Result get_hash_nid(uint32_t hash_size, int32_t *hash_nid)
{
    if (hash_size == SHA256_LEN) {
        *hash_nid = NID_sha256;
    } else if (hash_size == SHA512_LEN) {
        *hash_nid = NID_sha512;
    } else {
        tloge("invalid hash size %u\n", hash_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_secure_img_verify_signature(const uint8_t *signaure, size_t signaure_size, const uint8_t *hash_result,
                                           size_t hash_result_size, const rsa_pub_key_t *public_key)
{
    int32_t ret;

    bool is_invalid = (signaure == NULL || hash_result == NULL || public_key == NULL);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t hash_nid = 0;
    TEE_Result result = get_hash_nid(hash_result_size, &hash_nid);
    if (result != TEE_SUCCESS)
        return result;

    ret = rsa_verify_digest((uint8_t *)signaure, (uint32_t)signaure_size, (uint8_t *)hash_result,
                            (uint32_t)hash_result_size, (const rsa_pub_key_t *)public_key,
                            (uint32_t)hash_result_size, hash_nid, RSA_PKCS1_PSS_PADDING);
    if (ret != 0) {
        tloge("signature VerifyDigest failed, errno = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    tlogd("signature VerifyDigest success\n");
    return TEE_SUCCESS;
}

static TEE_Result config_cert_cn_ou_check(const struct cert_subjects *subjects,
                                          bool is_oh, bool is_sys_ta)
{
    TEE_Result ret;

    if (is_oh)
        ret = oh_conf_cert_cn_check(subjects->cn, subjects->cn_size);
    else
        ret = tee_secure_img_conf_cert_cn_check(subjects->cn, subjects->cn_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to pass ta developer alliance certificate CN check\n");
        return TEE_ERROR_GENERIC;
    }

#ifdef DYN_IMPORT_CERT
    if (!is_sys_ta)
        return TEE_SUCCESS;
#else
    (void)is_sys_ta;
#endif

    if (is_oh)
        ret = oh_conf_cert_ou_check(subjects->ou, subjects->ou_size, &g_conf_cert_type);
    else
        ret = tee_secure_img_conf_cert_ou_check(subjects->ou, subjects->ou_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to pass ta developer alliance certificate OU check\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_config_header(const struct ta_package *package,
                                    struct config_header *header)
{
    uint32_t magic;
    errno_t rc;

    bool is_invalid = (package->package_size <= sizeof(*header) - sizeof(header->version));
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    magic = *(uint32_t *)package->config_package;
    if (magic != TA_CONFIG_SEGMENT_MAGIC) {
        tloge("invliad config segment header data");
        return TEE_ERROR_GENERIC;
    }

    header->version = *(uint16_t *)(package->config_package + sizeof(magic));
    if (header->version == CONFIG_HEADER_V1) {
        rc = memcpy_s(&header->header.v1, sizeof(header->header.v1),
            package->config_package, sizeof(header->header.v1));
    } else if (header->version == CONFIG_HEADER_V2) {
        rc = memcpy_s(&header->header.v2, sizeof(header->header.v2),
            package->config_package, sizeof(header->header.v2));
    } else {
        tloge("Unsupported header version %u", header->version);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    return TEE_SUCCESS;
}

#define OFFSET_MAX_VAL  0xFFFFFFFF
static TEE_Result check_and_get_off_val(uint32_t *offset, uint32_t off_len, uint32_t allow_len)
{
    if (*offset > OFFSET_MAX_VAL - off_len) {
        tloge("off len is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *offset += off_len;
    if (*offset > allow_len) {
        tloge("off set is too long\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_cert_subjects(const uint8_t *cert, uint32_t cert_len, struct cert_subjects *subjects)
{
    int32_t len;

    /* Get cn from the certificate */
    len = get_subject_CN(subjects->cn, subjects->cn_size, cert, cert_len);
    if (len < 0) {
        tloge("Failed to get CN from certificate: %d\n", len);
        return TEE_ERROR_GENERIC;
    }
    subjects->cn_size = (uint32_t)len;

    /* Get OU from the certificate */
    len = get_subject_OU(subjects->ou, subjects->ou_size, cert, cert_len);
    if (len < 0) {
        tloge("Failed to validate certificate, length: %d\n", len);
        return TEE_ERROR_GENERIC;
    }
    subjects->ou_size = (uint32_t)len;

    return TEE_SUCCESS;
}

static TEE_Result ta_cert_cn_ou_check(const struct cert_subjects *subjects, const struct ta_identity *identity,
    cert_param_t *cert_param, bool is_oh)
{
    TEE_Result ret;

    ret = tee_secure_img_ta_cn_check(subjects->cn, subjects->cn_size,
        &identity->uuid, identity->service_name, identity->service_name_len);
    if (ret != TEE_SUCCESS)
        return ret;
#ifdef DYN_IMPORT_CERT
    if (!cert_param->sys_verify_ta)
        return TEE_SUCCESS;
#endif
    if (is_oh)
        ret = oh_ta_cert_ou_check(subjects->ou, subjects->ou_size, &cert_param->cert_type);
    else
        ret = tee_secure_img_ta_cert_ou_check(subjects->ou, subjects->ou_size, &cert_param->cert_type);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

static TEE_Result check_ta_cert_subjects(struct ta_config_info *config,
    const struct ta_identity *identity, struct perm_config *perm_config, cert_param_t *cert_param)
{
    TEE_Result ret;
    const uint8_t *cert = config->ta_cert.cert;
    uint32_t cert_len = config->ta_cert.cert_len;
    struct cert_subjects subjects = { { 0 }, 0, { 0 }, 0 };
    subjects.cn_size = (uint32_t)sizeof(subjects.cn);
    subjects.ou_size = (uint32_t)sizeof(subjects.ou);

    ret = get_cert_subjects(cert, cert_len, &subjects);
    if (ret != TEE_SUCCESS)
        return ret;

    errno_t rc = memcpy_s(perm_config->cn, sizeof(perm_config->cn), subjects.cn, subjects.cn_size);
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    perm_config->cn_size = subjects.cn_size;

    bool is_oh = false;
    if (config->header.version == CONFIG_HEADER_V1)
        is_oh = ((config->header.header.v1.policy_version & PRODUCT_BIT_MAP) == CONFIG_POLICY_OH) ? true : false;
    ret = ta_cert_cn_ou_check(&subjects, identity, cert_param, is_oh);
    if (ret != TEE_SUCCESS)
        return ret;

    perm_config->cert_type = cert_param->cert_type;

    return TEE_SUCCESS;
}

#ifdef DYN_IMPORT_CERT
static TEE_Result get_imported_crt_pubkey(uint8_t *dst, uint32_t *len)
{
    uint32_t crt_len = 0;
    int32_t ret;
    uint8_t crt_data[MAX_CRT_LEN] = { 0 };
    /* export certification data in bytes from ssa */
    if (export_cert_from_storage(crt_data, &crt_len, MAX_CRT_LEN) != TEE_SUCCESS) {
        tloge("get cert form ssa failed");
        return TEE_ERROR_GENERIC;
    }

    /* parse public key from data */
    ret = get_subject_public_key_new(dst, MAX_CRT_LEN, crt_data, crt_len);
    if (ret <= 0) {
        tloge("get public key form cert failed");
        return TEE_ERROR_GENERIC;
    } else {
        *len = (uint32_t)ret;
    }

    return TEE_SUCCESS;
}
#endif

static TEE_Result get_ta_pubkey_from_diff_plat(struct ta_config_info *config, cert_param_t *cert_param,
                                               uint8_t **ca_public_key, uint32_t *ca_public_key_len)
{
    bool is_oh = false;
    uint32_t sign_sec_alg;
    if (config->header.version == CONFIG_HEADER_V1) {
        sign_sec_alg = config->header.header.v1.signature_len >> SIGN_CONFIG_ALG_BITS;
        is_oh = ((config->header.header.v1.policy_version & PRODUCT_BIT_MAP) == CONFIG_POLICY_OH) ? true : false;
    }

    if (is_oh) {
        cert_param->cert_product_type = OH_CA_TYPE;
        if (g_ca_type == CA_PUBLIC) {
            *ca_public_key = (uint8_t *)get_pub_ca_key(sign_sec_alg);
            *ca_public_key_len = get_pub_ca_key_size(sign_sec_alg);
        } else {
            *ca_public_key = (uint8_t *)get_priv_ca_key(sign_sec_alg);
            *ca_public_key_len = get_priv_ca_key_size(sign_sec_alg);
        }
    } else {
        cert_param->cert_product_type = TEE_CA_TYPE;
        *ca_public_key = (uint8_t *)get_ca_pubkey();
        *ca_public_key_len = get_ca_pubkey_size();
    }
    if (*ca_public_key == NULL || *ca_public_key_len == 0) {
        tloge("failed to get ca public key\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static TEE_Result ta_cert_verify(struct ta_config_info *config, cert_param_t *cert_param,
    const struct ta_identity *identity, struct perm_config *perm_config)
{
    TEE_Result ret;
    const uint8_t *cert = config->ta_cert.cert;
    uint32_t cert_len = config->ta_cert.cert_len;
    uint8_t buff[CERT_ARRAY_SIZE] = {0};
    uint32_t buff_len = (uint32_t)sizeof(buff);
    uint8_t *ca_public_key = NULL;
    uint32_t ca_public_key_len;
#ifdef DYN_IMPORT_CERT
    if (!cert_param->sys_verify_ta) {
        cert_param->cert_product_type = IMPORT_CA_TYPE;
        uint8_t tmp_pubkey_buff[MAX_CRT_LEN] = { 0 };
        ca_public_key = tmp_pubkey_buff;
        ret = get_imported_crt_pubkey(tmp_pubkey_buff, &ca_public_key_len);
        if (ret != TEE_SUCCESS)
            ret = get_ta_pubkey_from_diff_plat(config, cert_param, &ca_public_key, &ca_public_key_len);
    } else {
        ret = get_ta_pubkey_from_diff_plat(config, cert_param, &ca_public_key, &ca_public_key_len);
    }
#else
    ret = get_ta_pubkey_from_diff_plat(config, cert_param, &ca_public_key, &ca_public_key_len);
#endif
    if (ret != TEE_SUCCESS)
        return ret;

    /* 1.validate ta cert with preload CA's public key, and check revoke status */
    ret = tee_secure_img_check_cert_validation(cert, cert_len, ca_public_key, ca_public_key_len);
    if (ret != TEE_SUCCESS)
        return ret;

    /* 2.check cert subjects cn and ou */
    ret = check_ta_cert_subjects(config, identity, perm_config, cert_param);
    if (ret != TEE_SUCCESS)
        return ret;

    /* 3.get the public key */
    if (get_subject_public_key_new(buff, sizeof(buff), cert, cert_len) < 0) {
        tloge("Failed to get subject public key from cert\n");
        return TEE_ERROR_GENERIC;
    }

    if (import_pub_from_sp(cert_param->public_key, buff, buff_len) < 0) {
        tloge("Failed to get public key from subject public key\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result ta_cert_info_verify(struct ta_config_info *config, cert_param_t *cert_param,
    const struct ta_identity *identity, struct perm_config *perm_config)
{
    if (config->ta_cert.type == TYPE_CERT)
        return ta_cert_verify(config, cert_param, identity, perm_config);

    tloge("Unsupported ta cert type %u", config->ta_cert.type);
    return TEE_ERROR_GENERIC;
}

static TEE_Result get_config_info_v1(const struct ta_package *package, struct ta_config_info *config)
{
    uint32_t offset = 0;
    uint32_t index;
    TEE_Result ret;

    config->ta_cert.type = TYPE_CERT;
    ret = check_and_get_off_val(&offset, sizeof(config->header.header.v1), package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    index = offset;
    ret = check_and_get_off_val(&offset, config->header.header.v1.ta_cert_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->ta_cert.cert = (uint8_t *)package->config_package + index;
    config->ta_cert.cert_len = config->header.header.v1.ta_cert_len;
    index = offset;

    ret = check_and_get_off_val(&offset, config->header.header.v1.config_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->tlv_config.data = (uint8_t *)(package->config_package) + index;
    config->tlv_config.len = config->header.header.v1.config_len;
    index = offset;

    uint32_t real_sig_len = config->header.header.v1.signature_len & CONFIG_SIGNATURE_LEN_MASK;
    /* 1: rsa_pkcsv15 2: rsa_pss 3: ecdsa */
    uint32_t algorithm = config->header.header.v1.signature_len >> SIGN_CONFIG_ALG_BITS;
    ret = check_and_get_off_val(&offset, real_sig_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->verify_data.signature = (uint8_t *)package->config_package + index;
    config->verify_data.signature_len = real_sig_len;
    index = offset;

    ret = check_and_get_off_val(&offset, config->header.header.v1.config_cert_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->verify_data.type = TYPE_CERT;
    if (config->verify_data.signature_len == ECC_SIGNATURE_LEN) {
        config->verify_data.sign_alg = SIGN_TYPE_ECDSA_SHA256;
    } else {
        config->verify_data.sign_alg = SIGN_TYPE_RSA_SHA256_PKCS1;
        if (algorithm == CONFIG_SIGN_ALG_RSA_PSS)
            config->verify_data.sign_alg = SIGN_TYPE_RSA_SHA256_PSS;
    }
    config->verify_data.cert = (uint8_t *)package->config_package + index;
    config->verify_data.cert_len = config->header.header.v1.config_cert_len;

    return TEE_SUCCESS;
}

static TEE_Result get_ta_cert(const uint8_t *data, uint32_t len, struct ta_cert_info *ta_cert)
{
    uint32_t offset = 0;
    TEE_Result ret;

    ret = check_and_get_off_val(&offset, sizeof(ta_cert->type), len);
    if (ret != TEE_SUCCESS) {
        tloge("parser ta cert info failed");
        return ret;
    }

    ta_cert->type = *((uint32_t *)data);

    ta_cert->cert_len = len - offset;
    ta_cert->cert = (uint8_t *)data + offset;

    return TEE_SUCCESS;
}

/*
 * signature verify segment struct as below:
 * +---------+
 * |-4 bytes-| type (0:public key; 1:cert; 2:cert chain;)
 * |-4 bytes-| sign algrithom
 * |-4 bytes-| cert len
 * |-n bytes-| cert content; n denpend on "cert len"
 * |-n bytes-| signature; n denpend on "sign algrithom"
 * +---------+
 */
static TEE_Result get_sign_verify_data(const uint8_t *data, uint32_t len, struct sign_verify_data *verify_data)
{
    uint32_t offset = 0;
    uint32_t index;
    TEE_Result ret;

    ret = check_and_get_off_val(&offset, sizeof(verify_data->type), len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->type = *((uint32_t *)data);
    index = offset;

    ret = check_and_get_off_val(&offset, sizeof(verify_data->sign_alg), len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->sign_alg = *((uint32_t *)(data + index));
    index = offset;

    ret = check_and_get_off_val(&offset, sizeof(verify_data->cert_len), len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->cert_len = *((uint32_t *)(data + index));
    index = offset;

    ret = check_and_get_off_val(&offset, verify_data->cert_len, len);
    if (ret != TEE_SUCCESS)
        return ret;

    verify_data->cert = (uint8_t *)data + index;
    index = offset;

    verify_data->signature = (uint8_t *)data + index;
    verify_data->signature_len = len - index;

    return TEE_SUCCESS;
}

/*
 * config segment sturct info as below:
 * +----------+
 * |-44 bytes-| header
 * |- n bytes-| ta cert info; n depends on value in header
 * |- n bytes-| tlv config data; n depends on value in header
 * |- n bytes-| signature verify data; n depends on value in header
 * +----------+
 */
static TEE_Result get_config_info_v2(const struct ta_package *package, struct ta_config_info *config)
{
    TEE_Result ret;
    uint32_t offset = 0;
    uint32_t index;

    ret = check_and_get_off_val(&offset, sizeof(config->header.header.v2), package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    index = offset;

    ret = check_and_get_off_val(&offset, config->header.header.v2.ta_cert_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = get_ta_cert(package->config_package + index, config->header.header.v1.ta_cert_len, &config->ta_cert);
    if (ret != TEE_SUCCESS)
        return ret;

    index = offset;
    ret = check_and_get_off_val(&offset, config->header.header.v2.config_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    config->tlv_config.data = (uint8_t *)package->config_package + index;
    config->tlv_config.len = config->header.header.v2.config_len;

    index = offset;
    ret = check_and_get_off_val(&offset, config->header.header.v2.config_verify_len, package->package_size);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = get_sign_verify_data(package->config_package + index,
        config->header.header.v2.config_verify_len, &config->verify_data);
    if (ret != TEE_SUCCESS) {
        tloge("parser sign verify data failed");
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result get_config_info(const struct ta_package *package, struct ta_config_info *config)
{
    if (config->header.version == CONFIG_HEADER_V1)
        return get_config_info_v1(package, config);
    else if (config->header.version == CONFIG_HEADER_V2)
        return get_config_info_v2(package, config);

    tloge("Unsupported header version: %u", config->header.version);
    return TEE_ERROR_BAD_PARAMETERS;
}

static TEE_Result check_config_cert_subjects(const uint8_t *cert, uint32_t cert_len,
                                             bool is_oh, const cert_param_t *cert_param)
{
    TEE_Result ret;
    struct cert_subjects subjects = { { 0 }, 0, { 0 }, 0 };
    subjects.cn_size = (uint32_t)sizeof(subjects.cn);
    subjects.ou_size = (uint32_t)sizeof(subjects.ou);

    ret = get_cert_subjects(cert, cert_len, &subjects);
    if (ret != TEE_SUCCESS)
        return ret;

    return config_cert_cn_ou_check(&subjects, is_oh, cert_param->sys_verify_ta);
}

uint32_t get_ca_type()
{
    return g_ca_type;
}

static TEE_Result check_oh_cert_validation(const struct ta_config_info *config,
        const uint8_t *cert, uint32_t cert_len)
{
    TEE_Result ret;
    uint32_t alg = config->header.header.v1.signature_len >> SIGN_CONFIG_ALG_BITS;
    uint8_t *pub_ca_key = (uint8_t *)get_pub_ca_key(alg);
    uint32_t pub_ca_key_size = get_pub_ca_key_size(alg);
    if (pub_ca_key == NULL || pub_ca_key_size == 0) {
        tloge("failed to get public ca key to verify config cert");
        return TEE_ERROR_GENERIC;
    }

    uint8_t *priv_ca_key = (uint8_t *)get_priv_ca_key(alg);
    uint32_t priv_ca_key_size = get_priv_ca_key_size(alg);
    if (priv_ca_key == NULL || priv_ca_key_size == 0) {
        tloge("failed to get private ca key to verify config cert");
        return TEE_ERROR_GENERIC;
    }

    /* 1.verify cert with parent key, and check cert revoked status */
    ret = tee_secure_img_check_cert_validation(cert, cert_len, pub_ca_key, pub_ca_key_size);
    if (ret != TEE_SUCCESS) {
        tlogd("config cert is not signed by public CA\n");
    } else {
        g_ca_type = CA_PUBLIC;
        return TEE_SUCCESS;
    }

    ret = tee_secure_img_check_cert_validation(cert, cert_len, priv_ca_key, priv_ca_key_size);
    if (ret != TEE_SUCCESS) {
        tloge("check cert validation failed\n");
        return ret;
    } else {
        g_ca_type = CA_PRIVATE;
        return TEE_SUCCESS;
    }
}

static TEE_Result check_config_cert_validation(const struct ta_config_info *config, const uint8_t *cert,
                                               uint32_t cert_len, uint8_t *key, const cert_param_t *cert_param)
{
    TEE_Result ret;
    uint8_t buff[CERT_ARRAY_SIZE] = { 0 };
    int32_t buff_len;
    bool is_oh = false;
    if (config->header.version == CONFIG_HEADER_V1)
        is_oh = ((config->header.header.v1.policy_version & PRODUCT_BIT_MAP) == CONFIG_POLICY_OH) ? true : false;

    if (is_oh) {
        ret = check_oh_cert_validation(config, cert, cert_len);
    } else {
        uint8_t *ca_key = (uint8_t *)get_ca_pubkey();
        uint32_t ca_key_size = get_ca_pubkey_size();
#ifdef DYN_IMPORT_CERT
        if (!cert_param->sys_verify_ta) {
            uint8_t tmp_pubkey_buff[MAX_CRT_LEN] = {0};
            ca_key = tmp_pubkey_buff;
            ret = get_imported_crt_pubkey(tmp_pubkey_buff, &ca_key_size);
            if (ret != TEE_SUCCESS)
                tloge("failed to get ca key from ssa");
        }
#endif
        if (ca_key == NULL || ca_key_size == 0) {
            tloge("failed to get ca public key to verify config cert");
            return TEE_ERROR_GENERIC;
        }
        /* 1.verify cert with parent key, and check cert revoked status */
        ret = tee_secure_img_check_cert_validation(cert, cert_len, ca_key, ca_key_size);
    }
    if (ret != TEE_SUCCESS) {
        tloge("failed to verify config cert");
        return ret;
    }

    /* 2.check cn and ou subjects */
    ret = check_config_cert_subjects(cert, cert_len, is_oh, cert_param);
    if (ret != TEE_SUCCESS)
        return ret;

    /* 3.get the public key */
    buff_len = get_subject_public_key_new(buff, sizeof(buff), cert, cert_len);
    if (buff_len < 0) {
        tloge("Failed to get subject public key from cert\n");
        return TEE_ERROR_GENERIC;
    }

    if (import_pub_from_sp(key, buff, buff_len) < 0) {
        tloge("Failed to get public key from subject public key\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result validate_sign_verify_data(const struct ta_config_info *config, const struct sign_verify_data *data,
                                            uint8_t *key, size_t key_size, const cert_param_t *cert_param)
{
    if (data->type == TYPE_PUB_KEY) {
        rsa_pub_key_t *temp = (rsa_pub_key_t *)get_config_pub_key();
        if (temp == NULL) {
            tloge("cannot get public key to verify config signature");
            return TEE_ERROR_GENERIC;
        }
        errno_t ret;
        ret = memcpy_s(key, key_size, temp, sizeof(*temp));
        if (ret != EOK)
            return TEE_ERROR_GENERIC;
        return TEE_SUCCESS;
    } else if (data->type == TYPE_CERT) {
        return check_config_cert_validation(config, data->cert, data->cert_len, key, cert_param);
    }

    tloge("Unsupported sign verify data type %u", data->type);
    return TEE_ERROR_GENERIC;
}

static TEE_Result get_data_hash_for_sign(const uint8_t *package, uint32_t package_len,
    const struct config_header *header,
    uint8_t *hash, uint32_t hash_len)
{
    (void)package_len;
    uint32_t len;

    /*
     * values in header already checked in parsering ta_config_info,
     * don't need to check reversal risk when calculating len
     */
    if (header->version == CONFIG_HEADER_V1)
        len = (uint32_t)sizeof(header->header.v1) + header->header.v1.ta_cert_len + header->header.v1.config_len;
    else if (header->version == CONFIG_HEADER_V2)
        len = (uint32_t)sizeof(header->header.v2) + header->header.v2.ta_cert_len + header->header.v2.config_len;
    else
        return TEE_ERROR_GENERIC;

    return tee_secure_img_calc_hash(package, len, hash, hash_len, TEE_ALG_SHA256);
}

static TEE_Result config_signature_verify_rsa(const struct ta_package *package,
                                              const struct ta_config_info *config,
                                              const cert_param_t *cert_param)
{
    TEE_Result ret;
    rsa_pub_key_t key = { { 0 }, 0, { 0 }, 0 };
    uint8_t hash[SHA256_LEN] = {0};
    uint32_t hash_len = (uint32_t)sizeof(hash);

    /* 1.check validation of config cert/ cert chain, and get public key to verify signature */
    ret = validate_sign_verify_data(config, &config->verify_data, (uint8_t *)&key, sizeof(key), cert_param);
    if (ret != TEE_SUCCESS) {
        tloge("check config cert rsa failed ");
        return ret;
    }

    /* 2.get hash value of data to be signed */
    ret = get_data_hash_for_sign(package->config_package, package->package_size, &config->header, hash, hash_len);
    if (ret != TEE_SUCCESS) {
        tloge("get hash failed");
        return ret;
    }

    /* 3.check signature validation */
    uint32_t padding;
    if (config->verify_data.sign_alg == SIGN_TYPE_RSA_SHA256_PSS)
        padding = RSA_PKCS1_PSS_PADDING;
    else
        padding = RSA_PKCS1_PADDING;
    if (rsa_verify_digest(config->verify_data.signature, (int32_t)config->verify_data.signature_len,
                          hash, hash_len, &key, hash_len, NID_sha256, padding) != 0) {
        tloge("rsa signature VerifyDigest failed, errno = 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result config_signature_verify_ecc(const struct ta_package *package,
                                              const struct ta_config_info *config,
                                              const cert_param_t *cert_param)
{
    TEE_Result ret;
    ecc_pub_key_t key = { 0, { 0 }, 0, { 0 }, 0 };
    uint8_t hash[SHA256_LEN] = {0};
    uint32_t hash_len = (uint32_t)sizeof(hash);

    /* 1.check validation of config cert/ cert chain, and get public key to verify signature */
    ret = validate_sign_verify_data(config, &config->verify_data, (uint8_t *)&key, sizeof(key), cert_param);
    if (ret != TEE_SUCCESS) {
        tloge("check config cert ecc failed ");
        return ret;
    }

    /* 2.get hash value of data to be signed */
    ret = get_data_hash_for_sign(package->config_package, package->package_size, &config->header, hash, hash_len);
    if (ret != TEE_SUCCESS) {
        tloge("get hash failed");
        return ret;
    }

    uint32_t i = 0;
    for (; i < config->verify_data.signature_len; i++) {
        if (config->verify_data.signature[i] == 0x00)
            continue;
        break;
    }

    /* 3.check signature validation */
    if (ecc_verify_digest(config->verify_data.signature + i, config->verify_data.signature_len - i,
                          hash, hash_len, &key) != 1) {
        tloge("ecc signature VerifyDigest failed");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result config_signature_verify(const struct ta_package *package,
                                          const struct ta_config_info *config,
                                          const cert_param_t *cert_param)
{
    if (config->verify_data.sign_alg == SIGN_TYPE_ECDSA_SHA256)
        return config_signature_verify_ecc(package, config, cert_param);
    else
        return config_signature_verify_rsa(package, config, cert_param);
}

static uint32_t get_policy_version(const struct config_header *header)
{
    if (header->version == CONFIG_HEADER_V1)
        return (uint32_t)header->header.v1.policy_version;
    else if (header->version == CONFIG_HEADER_V2)
        return (uint32_t)header->header.v2.policy_version;

    return 0;
}

TEE_Result ta_conf_package_process(const TEE_UUID *uuid,
    const struct ta_package *package, cert_param_t *cert_param)
{
    TEE_Result ret;
    struct ta_config_info config;
    struct perm_config perm_config = {0};
    struct ta_identity ta_identity = { { 0 }, NULL, 0 };

    (void)memset_s(&config, sizeof(config), 0, sizeof(config));
    bool is_invalid = (uuid == NULL || package == NULL || package->config_package == NULL ||
                       cert_param == NULL || package->name == NULL);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    /* 1.get header info of config segment */
    ret = get_config_header(package, &config.header);
    if (ret != TEE_SUCCESS) {
        tloge("parser config header failed");
        return ret;
    }

    /* 2.parser config segment to config info structure */
    ret = get_config_info(package, &config);
    if (ret != TEE_SUCCESS) {
        tloge("parser config info failed");
        return ret;
    }

    /* 3.verify the signature of config segment */
    ret = config_signature_verify(package, &config, cert_param);
    if (ret != TEE_SUCCESS)
        return ret;

    ta_identity.uuid = *uuid;
    ta_identity.service_name = (uint8_t *)package->name;
    ta_identity.service_name_len = package->name_len;
    /*
     * 4.check validation of ta cert:
     *  a)verify cert with CA's public key and revoked status
     *  b)check cert subjects with ta identity (uuid and service name)
     *  c)get cn content and cert type to check with config tlv content
     *  d)and get public key to verify elf segment in later process
     */
    ret = ta_cert_info_verify(&config, cert_param, &ta_identity, &perm_config);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to pass certificate validation check 0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    perm_config.tlv_buf = config.tlv_config.data;
    perm_config.tlv_len = config.tlv_config.len;
    perm_config.policy_version = get_policy_version(&config.header);

    /* 5.parser permissions in config tlv data segment */
    ret = parse_conf_body(uuid, &perm_config);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to parse configure body\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result tee_ext_set_config(const uint8_t *conf, uint32_t conf_len, const TEE_UUID *uuid,
    const uint8_t *service_name, uint32_t service_name_len, void *cert_param)
{
    struct ta_package package;

    if (conf == NULL || cert_param == NULL || uuid == NULL || service_name == NULL) {
        tloge("tee ext set config recv bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (conf_len == 0 || service_name_len == 0 || service_name_len > TA_CERT_MAX_SERVICE_NAME_LEN) {
        tloge("tee ext set config recv bad parameter, size error!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    package.config_package = conf;
    package.package_size = conf_len;
    package.name = service_name;
    package.name_len = service_name_len;
    return ta_conf_package_process(uuid, &package, (cert_param_t *)cert_param);
}
