/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Root of Trust Service.
 * Author: t00360454
 * Create: 2020-02-12
 * History: 2020-02-12 t00360454 create.
 */
#include "rot_public.h"
#include "rot_apdu.h"
#include <stdarg.h>
#include <procmgr_ext.h>
#include "securec.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_service_public.h"

/* APDU command definition */
enum APDU_INSTRUCTION {
    INS_IMPORT_KEY = 0x10,
    INS_EXPORT_CERT = 0x11,
    INS_SIGN = 0x12,
    INS_VERIFY = 0x13,
    INS_DEVICE_IDS = 0x14,
    INS_GENERATE_KEY = 0x15,
    INS_EXPORT_KEY = 0x16,
    INS_COMPUTE_MAC = 0x17,
    INS_COMPARE_MAC = 0x18,
    INS_CIPHER = 0x19,
    INS_CERT_EXIST = 0x1A,
    INS_ATTEST_KEY = 0x1B,
    INS_GET_BLOB_HANDLE = 0x1C
};
#define CLA_DEFAULT 0x00
#define P1_DEFAULT 0x00
#define P2_DEFAULT 0x00
#define P2_STORE_IDS 0x00
#define P2_VERIFY_IDS 0xFF
#define P2_ENCRYPT 0x00
#define P2_DECRYPT 0xFF
#define P2_GENERATE_APP_KEY 0xFF

/* Tags definition */
enum BER_TAG {
    TAG_MIN = 0xC0,
    TAG_KEY_PARAMS = TAG_MIN,
    TAG_IMPORT_KEY_CERT,
    TAG_UUID,
    TAG_BLOB_HANDLE,
    TAG_ALGO_MODE,
    TAG_MSG_DATA,
    TAG_IV,
    TAG_PADDING,
    TAG_SIGNATURE,
    TAG_MAC,
    TAG_AUTH_LIST,
    TAG_DEVICE_IDS,
    TAG_KEY_TYPE,
    TAG_MAX
};

#define MIN_PARAMS_NUM 1
#define MAX_PARAMS_NUM (TAG_MAX - TAG_MIN)
#define MAX_UINT32_VALUE (uint32_t)0xFFFFFFFF

/* package parameter structure */
enum data_type {
    TYPE_TLV = 0,
    TYPE_TLV_U32 = 1,
    TYPE_V = 2
};

struct memref_data {
    uint32_t type;          /* indicate the type of data: TLV, TLV_U32, V */
    uint8_t tag;
    struct memref_in mem;
    uint32_t value;
};

struct params_manager {
    uint32_t length;            /* the length of data has been used */
    uint32_t max_size;          /* array size of data */
    struct memref_data *data;   /* array data */
    uint32_t total_size;        /* the memory size required for all parameters */
    uint8_t cla;                /* apdu header's CLASS */
    uint8_t ins;                /* apdu header's INSTRUCTION */
    uint8_t p1;                 /* apdu header's Parameter1 */
    uint8_t p2;                 /* apdu header's Parameter2 */
};

/* Cipher parameter structure */
struct cipher_params {
    struct memref_in *blob_handle;
    struct algo_modes *mode_params;
    struct memref_in *data;
    struct memref_in *iv;
};

#ifdef CONFIG_GENERIC_ROT

/*
 * @brief     : get the caller uuid.
 * @param[out]: uuid, current uuid.
 * @return    : Operation status, success(0) or other failure status.
 */
static TEE_Result get_uuid(TEE_UUID *uuid)
{
    int ret;
    pid_t pid;
    spawn_uuid_t spawn_uuid = {0};

    pid = hm_getpid();
    if (pid < 0) {
        tloge("rot, %s, pid failed: %x\n", __func__, pid);
        return TEE_FAIL;
    }
    ret = hm_getuuid(pid, &spawn_uuid);
    if (ret < 0) {
        tloge("rot, %s, uuid failed: %x\n", __func__, ret);
        return TEE_FAIL;
    }
    *uuid = spawn_uuid.uuid;
    return TEE_SUCCESS;
}

/*
 * @brief        : send apdu message to agent host and check the result.
 * @param[in]    : capdu, apdu command message.
 * @param[in]    : capdu_len, the length of apdu command in bytes.
 * @param[out]   : rapdu, the buffer of apdu response data.
 * @param[in/out]: rapdu_len, the rapdu maximum size in bytes for input, the real size of rapdu in bytes for output.
 * @return       : Operation status, success(0) or other failure status.
 */
static TEE_Result send_apdu_message(const uint8_t *capdu, uint32_t capdu_len, uint8_t *rapdu, uint32_t *rapdu_len)
{
    tee_service_ipc_msg msg = { {0} };
    tee_service_ipc_msg_rsp rsp = { 0 };

    msg.args_data.arg0 = (uintptr_t)capdu;
    msg.args_data.arg1 = capdu_len;
    msg.args_data.arg2 = (uintptr_t)rapdu;
    msg.args_data.arg3 = (uintptr_t)rapdu_len;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(ROT_TASK_NAME, ROT_MSG_EXT_SEND_CMD, &msg, ROT_MSG_EXT_SEND_CMD, &rsp);
    if (rsp.ret != TEE_SUCCESS) {
        tloge("rot, %s, failed: %x\n", __func__, rsp.ret);
        return rsp.ret;
    }

    return TEE_SUCCESS;
}

/*
 * @brief         : check size and update the total size.
 * @param[in/out] : params_mgr, input and output parameters.
 * @param[in]     : tag, TLV's T.
 * @param[in]     : length, TLV's L.
 * @return        : true or false.
 */
static BOOL params_size_update(struct params_manager *params_mgr, uint8_t tag, uint32_t length)
{
    uint32_t size;

    if (tag != TAG_MAX)
        size = bertlv_size(tag, length);
    else
        size = length;

    if (params_mgr->total_size > MAX_UINT32_VALUE - size) {
        tloge("rot, %s, size error: %x, %x, %x\n", __func__, tag, params_mgr->total_size, size);
        return FALSE;
    }

    if (params_mgr->length >= params_mgr->max_size) {
        tloge("rot, %s, length error: %x, %x, %x\n", __func__, tag, params_mgr->max_size, params_mgr->length);
        return FALSE;
    }

    params_mgr->total_size += size;
    return TRUE;
}

/*
 * @brief         : add param data with type to parameters manager.
 * @param[in/out] : params_mgr, input and output parameters.
 * @param[in]     : type, the type of data to be appended.
 * @param[in]     : tag, TLV's T.
 * @param[in]     : value, TLV's L and V.
 * @return        : true or false.
 */
static BOOL params_append_with_type(struct params_manager *params_mgr, enum data_type type, uint8_t tag,
                                    const struct memref_in *value)
{
    uint32_t offset = params_mgr->length;

    /* do nothing */
    if (!value)
        return TRUE;

    if (params_size_update(params_mgr, tag, value->size) != TRUE)
        return FALSE;

    params_mgr->data[offset].type = type;
    params_mgr->data[offset].tag = tag;
    params_mgr->data[offset].mem.buffer = value->buffer;
    params_mgr->data[offset].mem.size = value->size;
    params_mgr->length++;

    return TRUE;
}

/*
 * @brief         : add data(TLV) to parameters manager.
 * @param[in/out] : params_mgr, input and output parameters.
 * @param[in]     : tag, TLV's T.
 * @param[in]     : value, TLV's L and V.
 * @return        : true or false.
 */
static BOOL params_append(struct params_manager *params_mgr, uint8_t tag, const struct memref_in *value)
{
    return params_append_with_type(params_mgr, TYPE_TLV, tag, value);
}

/*
 * @brief         : add data(V) to parameters manager.
 * @param[in/out] : params_mgr, input and output parameters.
 * @param[in]     : value, TLV's L and V.
 * @return        : true or false.
 */
static BOOL params_append_v(struct params_manager *params_mgr, const struct memref_in *value)
{
    return params_append_with_type(params_mgr, TYPE_V, TAG_MAX, value);
}

/*
 * @brief         : add data(u32) to parameters manager.
 * @param[in/out] : params_mgr, input and output parameters.
 * @param[in]     : tag, TLV's T.
 * @param[in]     : value, TLV's V.
 * @return        : Operation status, success(0) or other failure status.
 */
static BOOL params_append_u32(struct params_manager *params_mgr, uint8_t tag, uint32_t value)
{
    uint32_t offset = params_mgr->length;

    if (params_size_update(params_mgr, tag, sizeof(value)) != TRUE)
        return FALSE;

    params_mgr->data[offset].type = TYPE_TLV_U32;
    params_mgr->data[offset].tag = tag;
    params_mgr->data[offset].value= value;
    params_mgr->length++;

    return TRUE;
}

/*
 * @brief         : Init parameters manager.
 * @param[in/out] : params_mgr, input and output parameters.
 * @param[in]     : data, memref_data.
 * @param[in]     : size, array size of data.
 * @param[in]     : append_uuid, append the current UUID or not.
 * @return        : TEE_SUCCES or others.
 */
static TEE_Result params_init(struct params_manager *params_mgr, const struct memref_data *data, uint32_t size,
                              bool append_uuid)
{
    TEE_Result ret;
    static TEE_UUID cur_uuid = {0};
    struct memref_in temp = {0};

    params_mgr->data = (struct memref_data *)data;
    params_mgr->max_size = size;
    params_mgr->length = 0;
    params_mgr->total_size = 0;

    if (!append_uuid)
        return TEE_SUCCESS;

    ret = get_uuid(&cur_uuid);
    if (ret != TEE_SUCCESS)
        return ret;
    temp.buffer = (uint8_t *)&cur_uuid;
    temp.size = sizeof(cur_uuid);
    if (!params_append(params_mgr, TAG_UUID, &temp))
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

/*
 * @brief         : append data to TLVer.
 * @param[in/out] : tlver, the constructed BER tlv byte array.
 * @param[in]     : data, input data to be added.
 * @return        : Operation status, success(0) or other failure status.
 */
static TEE_Result data_append(struct ber_tlv *tlver, const struct memref_data *data)
{
    TEE_Result ret;

    if (!data) {
        tloge("rot, %s, null pointer: %x, %x\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (data->type) {
        case TYPE_TLV:
            ret = apdu_ext_body_append_tlv(tlver, data->tag, data->mem.size, data->mem.buffer);
            break;
        case TYPE_TLV_U32:
            ret = apdu_ext_body_append_u32(tlver, data->tag, data->value);
            break;
        case TYPE_V:
            ret = apdu_ext_body_append_v(tlver, data->mem.size, data->mem.buffer);
            break;
        default:
            ret = TEE_SUCCESS;
            break;
    }

    return ret;
}

/*
 * @brief       : package Command APDU by the parameters manager.
 * @param[out]  : msg, the apdu message.
 * @param[in]   : params_mgr, input and output parameters.
 * @return      : Operation status, success(0) or other failure status.
 */
static TEE_Result package_apdu(struct apdu_message *msg, const struct params_manager *params_mgr)
{
    TEE_Result ret;
    struct ber_tlv tlver = {0};
    uint32_t i;

    /* APDU header */
    ret = apdu_ext_set_header(msg, params_mgr->cla, params_mgr->ins, params_mgr->p1, params_mgr->p2);
    if (ret != TEE_SUCCESS)
        return ret;

    /* APDU body */
    ret = apdu_ext_body_init(&tlver, msg);
    if (ret != TEE_SUCCESS)
        return ret;

    for (i = 0; i < params_mgr->length; i++) {
        ret = data_append(&tlver, &params_mgr->data[i]);
        if (ret != TEE_SUCCESS)
            return ret;
    }

    return apdu_ext_body_append_end(&tlver, msg);
}

/*
 * @brief         : package capdu, send it and unpackage rapdu.
 * @param[in/out] : params_mgr, input and output parameters.
 * @param[in/out] : response, the buffer to store the response data..
 * @return        : Operation status, success(0) or other failure status.
 */
static TEE_Result execute_apdu_command(struct params_manager *params_mgr, struct memref_out *response)
{
    TEE_Result ret;
    struct apdu_message msg = {0};
    uint32_t capdu_len;
    uint32_t rapdu_len;
    uint8_t *resp_buffer = NULL;
    uint32_t *resp_size = NULL;

    if (response) {
        resp_buffer = response->buffer;
        resp_size = response->size;
    }

    /* alloc apdu message */
    capdu_len = apdu_ext_calc_size(params_mgr->total_size);
    if (capdu_len == 0)
        return TEE_ERROR_BAD_PARAMETERS;
    if (!resp_size)
        rapdu_len = apdu_ext_get_response_size(0);
    else
        rapdu_len = apdu_ext_get_response_size(*resp_size);

    ret = apdu_ext_alloc_message(&msg, capdu_len, rapdu_len);
    if (ret != TEE_SUCCESS)
        goto message_clear;

    /* package Command APDU */
    ret = package_apdu(&msg, params_mgr);
    if (ret != TEE_SUCCESS)
        goto message_clear;

    /* execute APDU */
    ret = send_apdu_message(msg.capdu, msg.capdu_len, msg.rapdu, msg.rapdu_len);
    if (ret != TEE_SUCCESS)
        goto message_clear;

    /* unpackage Response APDU */
    ret = apdu_ext_unpackage_rapdu(&msg, resp_buffer, resp_size);

message_clear:
    apdu_ext_clear_message(&msg);
    return ret;
}

/*
 * @brief    : Store or verify Device IDs.
 * @param[in]: ids, the device's IDs info.
 * @param[in]: p2, apdu header parameter2.
 * @return   : Operation status, success(0) or other failure status.
 */
static TEE_Result tee_ext_operate_ids(const struct memref_in *ids, uint8_t p2)
{
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MIN_PARAMS_NUM] = { {0} };

    if (!ids || !ids->buffer)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), false);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append_v(&params_mgr, ids);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_DEVICE_IDS;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = p2;

    return execute_apdu_command(&params_mgr, NULL);
}

/*
 * @brief     : symmetric or asymmetric cipher Encryption.
 * @param[in] : params, input parameters.
 * @param[in] : p2, apdu header parameter2.
 * @param[out]: out_data, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
static TEE_Result tee_ext_rot_cipher(struct cipher_params *params, uint8_t p2, struct memref_out *out_data)
{
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!params || !params->blob_handle || !params->blob_handle->buffer || !params->mode_params || !params->data ||
        !params->data->buffer || !out_data || !out_data->buffer || !out_data->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, params->blob_handle);
    status &= params_append_u32(&params_mgr, TAG_ALGO_MODE, params->mode_params->mode);
    status &= params_append_u32(&params_mgr, TAG_PADDING, params->mode_params->padding);
    status &= params_append(&params_mgr, TAG_MSG_DATA, params->data);
    status &= params_append(&params_mgr, TAG_IV, params->iv);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_CIPHER;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = p2;

    return execute_apdu_command(&params_mgr, out_data);
}
#endif

/*
 * @brief    : Store Device IDs.
 * @param[in]: ids, the device's IDs info to be stored.
 * @return   : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTStoreID(const struct memref_in *ids)
{
#ifdef CONFIG_GENERIC_ROT
    return tee_ext_operate_ids(ids, P2_STORE_IDS);
#else
    (void)ids;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief    : Verify the Device IDs.
 * @param[in]: ids, the device's IDs info to be stored.
 * @return   : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTVerifyID(const struct memref_in *ids)
{
#ifdef CONFIG_GENERIC_ROT
    return tee_ext_operate_ids(ids, P2_VERIFY_IDS);
#else
    (void)ids;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Generate Key.
 * @param[in] : parameters, key information, data is arranged in big-endian mode.
 *              see structure key_params for details.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTGenerateKey(const struct memref_in *params, struct memref_out *blob_handle)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!params || !params->buffer || !blob_handle || !blob_handle->buffer || !blob_handle->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_KEY_PARAMS, params);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_GENERATE_KEY;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, blob_handle);
#else
    (void)params;
    (void)blob_handle;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Generate App Key.
 * @param[in] : parameters, key information, data is arranged in big-endian mode.
 *              see structure key_params for details.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTGenerateAppKey(const struct memref_in *params, struct memref_out *blob_handle)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = true;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!params || !params->buffer || !blob_handle || !blob_handle->buffer || !blob_handle->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_KEY_PARAMS, params);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_GENERATE_KEY;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_GENERATE_APP_KEY;

    return execute_apdu_command(&params_mgr, blob_handle);
#else
    (void)params;
    (void)blob_handle;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Import Key and Certs.
 * @param[in] : parameters, key information, data is arranged in big-endian mode.
 *              see structure key_params for details.
 * @param[in] : cert, standard X.509 Certs.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTImportKey(const struct memref_in *params, const struct memref_in *cert,
                                struct memref_out *blob_handle)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!params || !params->buffer || !cert || !cert->buffer || !blob_handle ||
        !blob_handle->buffer || !blob_handle->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_KEY_PARAMS, params);
    status &= params_append(&params_mgr, TAG_IMPORT_KEY_CERT, cert);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_IMPORT_KEY;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, blob_handle);
#else
    (void)params;
    (void)cert;
    (void)blob_handle;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Export Public Key.
 * @param[in] : blob_handle, the handle of key information.
 * @param[out]: pub_key, public key.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTExportKey(const struct memref_in *blob_handle, struct memref_out *pub_key)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || !pub_key || !pub_key->buffer || !pub_key->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_EXPORT_KEY;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, pub_key);
#else
    (void)blob_handle;
    (void)pub_key;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Export Certs.
 * @param[in] : blob_handle, the handle of key information.
 * @param[out]: cert, standard X.509 Certs.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTExportCert(const struct memref_in *blob_handle, struct memref_out *cert)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || !cert || !cert->buffer || !cert->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_EXPORT_CERT;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, cert);
#else
    (void)blob_handle;
    (void)cert;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Generate signature.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode, the calc mode for signed.
 * @param[in] : digest, the digest data to be signed.
 * @param[out]: out_data, the signature buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTSign(const struct memref_in *blob_handle, uint32_t mode, const struct memref_in *digest,
                           struct memref_out *out_data)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || !digest || !digest->buffer || !out_data ||
        !out_data->buffer || !out_data->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    status &= params_append_u32(&params_mgr, TAG_ALGO_MODE, mode);
    status &= params_append(&params_mgr, TAG_MSG_DATA, digest);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_SIGN;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, out_data);
#else
    (void)blob_handle;
    (void)mode;
    (void)digest;
    (void)out_data;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Verifies the signature.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode, the clac mode for verified.
 * @param[in] : digest, the digest data to be verified.
 * @param[out]: signature, the signature data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTVerify(const struct memref_in *blob_handle, uint32_t mode, const struct memref_in *digest,
                             const struct memref_in *signature)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || !digest || !digest->buffer || !signature || !signature->buffer)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    status &= params_append_u32(&params_mgr, TAG_ALGO_MODE, mode);
    status &= params_append(&params_mgr, TAG_MSG_DATA, digest);
    status &= params_append(&params_mgr, TAG_SIGNATURE, signature);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_VERIFY;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, NULL);
#else
    (void)blob_handle;
    (void)mode;
    (void)digest;
    (void)signature;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Generate MAC.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for MACed.
 * @param[in] : data, the message data to be MACed.
 * @param[in] : iv, the init vector data.
 * @param[out]: mac, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTComputeMAC(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                                 const struct memref_in *data, const struct memref_in *iv, struct memref_out *mac)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || !mode_params || !data || !data->buffer ||
        !mac || !mac->buffer || !mac->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    status &= params_append_u32(&params_mgr, TAG_ALGO_MODE, mode_params->mode);
    status &= params_append_u32(&params_mgr, TAG_PADDING, mode_params->padding);
    status &= params_append(&params_mgr, TAG_MSG_DATA, data);
    status &= params_append(&params_mgr, TAG_IV, iv);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_COMPUTE_MAC;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, mac);
#else
    (void)blob_handle;
    (void)mode_params;
    (void)data;
    (void)iv;
    (void)mac;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Genearte MAC and compare the MAC.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for MACed.
 * @param[in] : data, the message data to be MACed.
 * @param[in] : iv, the init vector data.
 * @param[in] : mac, the input MAC to be compared.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTCompareMAC(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                                 const struct memref_in *data, const struct memref_in *iv, const struct memref_in *mac)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || !mode_params || !data || !data->buffer || !mac || !mac->buffer)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    status &= params_append_u32(&params_mgr, TAG_ALGO_MODE, mode_params->mode);
    status &= params_append_u32(&params_mgr, TAG_PADDING, mode_params->padding);
    status &= params_append(&params_mgr, TAG_MSG_DATA, data);
    status &= params_append(&params_mgr, TAG_IV, iv);
    status &= params_append(&params_mgr, TAG_MAC, mac);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_COMPARE_MAC;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, NULL);
#else
    (void)blob_handle;
    (void)mode_params;
    (void)data;
    (void)iv;
    (void)mac;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : symmetric or asymmetric cipher Encryption.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for Cipher, padding mode used only for symmetric algo.
 * @param[in] : in_data, the message data to be Encrypted.
 * @param[in] : iv, the init vector data, ignored for asymmetric algo.
 * @param[out]: out_data, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTEncrypt(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                              const struct memref_in *in_data, const struct memref_in *iv, struct memref_out *out_data)
{
#ifdef CONFIG_GENERIC_ROT
    struct cipher_params params = { 0 };

    params.blob_handle = (struct memref_in *)blob_handle;
    params.mode_params = (struct algo_modes *)mode_params;
    params.data = (struct memref_in *)in_data;
    params.iv = (struct memref_in *)iv;
    return tee_ext_rot_cipher(&params, P2_ENCRYPT, out_data);
#else
    (void)blob_handle;
    (void)mode_params;
    (void)in_data;
    (void)iv;
    (void)out_data;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : symmetric or asymmetric cipher Decryption.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : mode_params, the clac mode and padding mode for Cipher, padding mode used only for symmetric algo.
 * @param[in] : in_data, the message data to be Encrypted.
 * @param[in] : iv, the init vector data, ignored for asymmetric algo.
 * @param[out]: out_data, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTDecrypt(const struct memref_in *blob_handle, const struct algo_modes *mode_params,
                              const struct memref_in *in_data, const struct memref_in *iv, struct memref_out *out_data)
{
#ifdef CONFIG_GENERIC_ROT
    struct cipher_params params = { 0 };

    params.blob_handle = (struct memref_in *)blob_handle;
    params.mode_params = (struct algo_modes *)mode_params;
    params.data = (struct memref_in *)in_data;
    params.iv = (struct memref_in *)iv;
    return tee_ext_rot_cipher(&params, P2_DECRYPT, out_data);
#else
    (void)blob_handle;
    (void)mode_params;
    (void)in_data;
    (void)iv;
    (void)out_data;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Get the Certs Exist or not.
 * @param[in] : blob_handle, the handle of key information.
 * @return    : exist if TEE_SUCCESS, non-exist if others.
 */
TEE_Result TEE_EXT_ROTCertExist(const struct memref_in *blob_handle)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_CERT_EXIST;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, NULL);
#else
    (void)blob_handle;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Key Attestion or ID Attestion.
 * @param[in] : blob_handle, the handle of key information.
 * @param[in] : auth_list, extensions data.
 * @param[in] : ids, device ids, ignored for Key Attest.
 * @param[out]: cert_chain, the output buffer.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTAttestKey(const struct memref_in *blob_handle, const struct memref_in *auth_list,
                                const struct memref_in *ids, struct memref_out *cert_chain)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || (!auth_list && !ids) || !cert_chain || !cert_chain->buffer ||
        !cert_chain->size)
        return TEE_ERROR_BAD_PARAMETERS;

    if ((auth_list && !auth_list->buffer) || (ids && !ids->buffer))
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append(&params_mgr, TAG_BLOB_HANDLE, blob_handle);
    status &= params_append(&params_mgr, TAG_AUTH_LIST, auth_list);
    status &= params_append(&params_mgr, TAG_DEVICE_IDS, ids);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_ATTEST_KEY;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, cert_chain);
#else
    (void)blob_handle;
    (void)auth_list;
    (void)ids;
    (void)cert_chain;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}

/*
 * @brief     : Get Key Blob Handle.
 * @param[in] : type, key type, such as RSA/ECC/AES.
 * @param[out]: blob_handle, the buffer of apdu response data.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result TEE_EXT_ROTGetBlobHandle(uint32_t type, struct memref_out *blob_handle)
{
#ifdef CONFIG_GENERIC_ROT
    TEE_Result ret;
    BOOL status = TRUE;
    struct params_manager params_mgr = { 0 };
    struct memref_data param_data[MAX_PARAMS_NUM] = { {0} };

    if (!blob_handle || !blob_handle->buffer || !blob_handle->size)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = params_init(&params_mgr, param_data, ARRAY_SIZE(param_data), true);
    if (ret != TEE_SUCCESS)
        return ret;

    status &= params_append_u32(&params_mgr, TAG_KEY_TYPE, type);
    if (!status)
        return TEE_ERROR_BAD_PARAMETERS;

    params_mgr.cla = CLA_DEFAULT;
    params_mgr.ins = INS_GET_BLOB_HANDLE;
    params_mgr.p1 = P1_DEFAULT;
    params_mgr.p2 = P2_DEFAULT;

    return execute_apdu_command(&params_mgr, blob_handle);
#else
    (void)type;
    (void)blob_handle;
    return TEE_ERROR_SERVICE_NOT_EXIST;
#endif
}
