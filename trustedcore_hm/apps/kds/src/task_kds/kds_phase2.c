/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Deal with kds phase two command.
 * Create: 2020-06-28
 */

#include "kds_phase2.h"
#include "tee_mem_mgmt_api.h"
#include "kds_defs.h"
#include "kds_core.h"

static char *g_trustPathList[] = {
    "/vendor/bin/atcmdserver",
    "/init",
    "/sbin/recovery",
    "/system/bin/hwnffserver",
    "/sbin/cust",
    "/sbin/cota",
    "/sbin/huawei_dload",
    "/sbin/factory_reset",
    "/sbin/cust_init",
    "/vendor/bin/oeminfo_nvm_server"
};

static uint8_t g_trustIdList[][TARGET_ID_LENGTH] = {
    { 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x35, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x36, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x38, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x39, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 },
    { 0x3A, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
      0x30, 0x30 }
};

TEE_Result AddCaller()
{
    uint32_t len = sizeof(g_trustPathList) / sizeof(g_trustPathList[0]);
    for (uint32_t i = 0; i < len; i++) {
        // To add the process to the trust list.
        if (AddCaller_CA_exec(g_trustPathList[i], 0) != TEE_SUCCESS) {
            SLogError("AddCaller_CA_exec failed\n");
            return TEE_FAIL;
        }
    }
    return TEE_SUCCESS;
}

static TEE_Result InputParamsizeCheckCA(TEE_Param *params)
{
    if ((params[INDEX_ZERO].memref.size != REQ_SIZE) ||
        (params[INDEX_ZERO].memref.buffer == NULL)) {
        SLogError("invalid param, param[0]\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    if ((params[INDEX_ONE].memref.size != DATA_SIZE) ||
        (params[INDEX_ONE].memref.buffer == NULL)) {
        SLogError("invalid param, param[1]\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    if ((params[INDEX_TWO].memref.size > MAX_PATH_LENGTH) ||
        (params[INDEX_TWO].memref.buffer == NULL)) {
        SLogError("invalid param, param[2]\n");
        return TEE_ERROR_BAD_FORMAT;
    }
    return TEE_SUCCESS;
}

static TEE_Result ParamCheckCA(uint32_t paramTypes, TEE_Param *params)
{
    if (TEE_PARAM_TYPE_GET(paramTypes, INDEX_ZERO) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(paramTypes, INDEX_ONE) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(paramTypes, INDEX_TWO) != TEE_PARAM_TYPE_MEMREF_INPUT) {
        SLogError("bad expected parameter types.");
        return TEE_ERROR_BAD_FORMAT;
    }

    TEE_Result ret = InputParamsizeCheckCA(params);
    if (ret != TEE_SUCCESS) {
        SLogError("InputParamsizeCheckCA failed");
        return ret;
    }
    /* check if params[3] is valid */
    KdsHukReqInfos *hukReqInfo = params[INDEX_ZERO].memref.buffer;
    if (hukReqInfo->reqType == KDS_REQ_HASH_VERIFY_HMAC_SHA256) {
        if (TEE_PARAM_TYPE_GET(paramTypes, INDEX_THREE) != TEE_PARAM_TYPE_NONE) {
            SLogError("bad expected parameter types.");
            return TEE_ERROR_BAD_FORMAT;
        }
    } else {
        if (TEE_PARAM_TYPE_GET(paramTypes, INDEX_THREE) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
            SLogError("bad expected parameter types.");
            return TEE_ERROR_BAD_FORMAT;
        }
        if (params[INDEX_THREE].memref.size != DATA_SIZE ||
            params[INDEX_THREE].memref.buffer == NULL) {
            SLogError("invalid param, param[3]\n");
            return TEE_ERROR_BAD_FORMAT;
        }
    }

    return TEE_SUCCESS;
}

static bool IsArrayEqual(const uint8_t *arrSrc, uint32_t arrSrcLen,
    const uint8_t *arrDst, uint32_t arrDstLen)
{
    if ((arrSrc == NULL) || (arrDst == NULL) || (arrSrcLen != arrDstLen)) {
        SLogError("param error");
        return false;
    }

    for (uint32_t i = 0; i < arrSrcLen; i++) {
        if (arrSrc[i] != arrDst[i]) {
            SLogError("arrSrc %x, arrDst %x", arrSrc[i], arrDst[i]);
            return false;
        }
    }
    return true;
}

/*
 * To check the if the reqType is suported by the kds.
 */
static int CheckReqType(uint32_t reqType)
{
    switch (reqType) {
        case KDS_REQ_ENCRYPT_AES_CBC_128:
        case KDS_REQ_DECRYPT_AES_CBC_128:
        case KDS_REQ_ENCRYPT_AES_CBC_256:
        case KDS_REQ_DECRYPT_AES_CBC_256:
        case KDS_REQ_HASH_GENERATE_HMAC_SHA256:
        case KDS_REQ_HASH_VERIFY_HMAC_SHA256:
            return KDS_OK;
        default:
            return KDS_ERROR_REQTYPE_UNSUPPORT;
    }
}

static KdsResultCode IdAuthCheck(const uint8_t *callerId, const uint8_t *targetId,
    uint32_t reqType)
{
    if (IsArrayEqual(callerId, TARGET_ID_LENGTH, targetId, TARGET_ID_LENGTH)) {
        if (CheckReqType(reqType) == KDS_OK) {
            SLogTrace("equal, ok");
            return KDS_SUCCESS;
        } else {
            SLogError("equal, not ok");
            return KDS_ERROR_REQTYPE_UNSUPPORT;
        }
    } else {
        switch (reqType) {
            case KDS_REQ_ENCRYPT_AES_CBC_128:
            case KDS_REQ_ENCRYPT_AES_CBC_256:
            case KDS_REQ_HASH_VERIFY_HMAC_SHA256:
                SLogTrace("not equal, ok");
                return KDS_SUCCESS;
            default:
                SLogError("not equal, not ok");
                return KDS_ERROR_REQTYPE_INVALID;
        }
    }
}

/*
 * Check if the callerPath is in the g_trustPathList and if the reqType is permitted.
 */
static TEE_Result KdsAuthCheck(const char *paramBuffer, const size_t paramSize, const KdsHukReqInfos *params)
{
    char *callerPath = NULL;
    size_t callerPathLen = paramSize + 1;
    callerPath = (char *)TEE_Malloc(callerPathLen, 0);
    if (callerPath == NULL) {
        SLogError("TEE_Malloc failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    int rc = memcpy_s(callerPath, callerPathLen, paramBuffer, paramSize);
    if (rc != EOK) {
        SLogError("memcpy_s failed, rc %d\n", rc);
        if (callerPath != NULL) {
            memset_s(&callerPath, callerPathLen, 0x00, callerPathLen);
            TEE_Free(callerPath);
            callerPath = NULL;
        }
        return KDS_AUTH_ERROR;
    }
    callerPath[callerPathLen - 1] = '\0';
    uint32_t len = sizeof(g_trustPathList) / sizeof(g_trustPathList[0]);
    for (uint32_t i = 0; i < len; i++) {
        if (strcmp(g_trustPathList[i], callerPath) != EOK) {
            continue;
        }
        if (callerPath != NULL) {
            memset_s(&callerPath, callerPathLen, 0x00, callerPathLen);
            TEE_Free(callerPath);
            callerPath = NULL;
        }
        KdsResultCode ret = IdAuthCheck(g_trustIdList[i], params->targetId, params->reqType);
        if (ret != KDS_SUCCESS) {
            SLogError("kds auth check faild, the reqType is invalid by the process");
            return KDS_AUTH_ERROR;
        }
        return KDS_SUCCESS;
    }
    SLogError("the process is not in the trust list!");
    if (callerPath != NULL) {
        memset_s(&callerPath, callerPathLen, 0x00, callerPathLen);
        TEE_Free(callerPath);
        callerPath = NULL;
    }
    return KDS_AUTH_ERROR;
}

static TEE_Result KdsDeriveDeviceKey(uint32_t keysize, uint8_t *outkey)
{
    if ((outkey == NULL) || (keysize == 0) || (keysize > MAIN_KEY_LENGTH)) {
        SLogError("KdsDeriveDeviceKey param invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t salt[SALT_SIZE] = {0};
    TEE_Result ret = TEE_EXT_DeriveTARootKey(salt, SALT_SIZE, outkey, keysize);
    if (ret != TEE_SUCCESS) {
        SLogError("TEE_EXT_DeriveTARootKey faild:0x%x", ret);
        return ret;
    }
    return ret;
}

static TEE_Result ConstructHamcMsg(const KdsHukReqInfos *params, uint32_t encType, uint8_t *msg,
    uint32_t msgLen)
{
    // Construct hmac msg, include targetId, driveFactor, encType.
    int ret = memcpy_s(msg, msgLen, params->targetId, TARGET_ID_LENGTH);
    if (ret != EOK) {
        SLogError("copy target id failed %x\n", ret);
        return TEE_FAIL;
    }

    ret = memcpy_s(msg + TARGET_ID_LENGTH, msgLen - TARGET_ID_LENGTH,
        params->driveFactor, DF_LENGTH);
    if (ret != EOK) {
        SLogError("copy derive factor failed %x\n", ret);
        return TEE_FAIL;
    }

    ret = memcpy_s(msg + TARGET_ID_LENGTH + DF_LENGTH,
        msgLen - TARGET_ID_LENGTH - DF_LENGTH,
        &encType, sizeof(uint32_t));
    if (ret != EOK) {
        SLogError("copy encrypt type failed %x\n", ret);
        return TEE_FAIL;
    }
    return TEE_SUCCESS;
}

// Use the mainkey to generate the reqkey.
static TEE_Result KdsGenerateReqkey(const DataBlob *mkBlob, const KdsHukReqInfos *params,
    DataBlob *hmacResult)
{
    uint32_t encType = 0;
    uint8_t msgBeforeHmac[HMAC_MSG_LENGTH] = {0};

    switch (params->reqType) {
        case KDS_REQ_ENCRYPT_AES_CBC_128:
        case KDS_REQ_DECRYPT_AES_CBC_128:
            encType = KDS_AES_128;
            break;
        case KDS_REQ_ENCRYPT_AES_CBC_256:
        case KDS_REQ_DECRYPT_AES_CBC_256:
            encType = KDS_AES_256;
            break;
        case KDS_REQ_HASH_GENERATE_HMAC_SHA256:
        case KDS_REQ_HASH_VERIFY_HMAC_SHA256:
            encType = KDS_HMAC;
            break;
        default:
            SLogError("invalid reqType:%x", params->reqType);
            return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = ConstructHamcMsg(params, encType, msgBeforeHmac, HMAC_MSG_LENGTH);
    if (ret != TEE_SUCCESS) {
        SLogError("construct msgBeforeHmac failed, ret %x", ret);
        return ret;
    }

    DataBlob msgBlob = { msgBeforeHmac, HMAC_MSG_LENGTH };
    ret = HmacSha256(&msgBlob, mkBlob, hmacResult);
    if (ret != TEE_SUCCESS) {
        SLogError("HMAC SHA256 failed, ret %x", ret);
        return ret;
    }

    // If the type is encrypt/decrypt 128, just use 128-bit.
    if (encType == KDS_AES_128) {
        hmacResult->len = (hmacResult->len) / DIVISION_NUM_TWO;
    }
    return ret;
}

static TEE_Result KdsReqEncryptAesCbc(const DataBlob *keyData, KdsHukDataInfos *hukData,
    KdsHukDataInfos *outData)
{
    if (hukData->data1Size > MAC_PLAINT_DATA_SIZE) {
        SLogError("KdsReqEncryptAesCbc invalid param size!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    outData->data1Size = sizeof(outData->data1); // cipher
    outData->data2Size = sizeof(outData->data2); // iv data, ramdomly generated
    DataBlob plantData = { hukData->data1, hukData->data1Size };
    AesCbcEncryptParams encryptParams = {
        outData->data1, &outData->data1Size,
        outData->data2, &outData->data2Size
    };
    TEE_Result ret = TaAesCbcEncrypt(keyData, &plantData, &encryptParams);
    if (ret != TEE_SUCCESS) {
        SLogError("TaAesCbcEncrypt error:0x%x", ret);
    }
    return ret;
}

static TEE_Result KdsReqDecryptAesCbc(const DataBlob *keyData, KdsHukDataInfos *hukData,
    KdsHukDataInfos *outData)
{
    if ((hukData->data1Size > MAX_HUK_DATA_SIZE) ||
        (hukData->data2Size > MAX_HUK_DATA_SIZE)) {
        SLogError("KdsReqDecryptAesCbc invalid paramsize!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    outData->data1Size = sizeof(outData->data1);
    const DataBlob ivData = { hukData->data2, hukData->data2Size };
    const DataBlob cipherData = { hukData->data1, hukData->data1Size };
    TEE_Result ret = AesDecrypt(keyData, &ivData, &cipherData, outData->data1,
        (size_t *)(&outData->data1Size));
    if (ret != TEE_SUCCESS) {
        SLogError("AesDecrypt failed ret = 0x%x", ret);
    }
    return ret;
}

static TEE_Result KdsReqGenHmacSha256(const DataBlob *keyData, KdsHukDataInfos *hukData,
    KdsHukDataInfos *outData)
{
    if (hukData->data1Size > MAX_HUK_DATA_SIZE) {
        SLogError("KdsReqGenHmacSha256 invalid param size!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    outData->data1Size = sizeof(outData->data1);
    const DataBlob msgBlob = { hukData->data1, hukData->data1Size };
    DataBlob hmacResult = { outData->data1, outData->data1Size };

    TEE_Result ret = HmacSha256(&msgBlob, keyData, &hmacResult);
    outData->data1Size = hmacResult.len;
    if (ret != TEE_SUCCESS) {
        SLogError("HmacSha256 failed!");
    }
    return ret;
}

static TEE_Result KdsReqVerifyHmacSha256(const DataBlob *keyData, KdsHukDataInfos *hukData)
{
    if ((hukData->data1Size > MAX_HUK_DATA_SIZE) ||
        (hukData->data2Size > MAX_HUK_DATA_SIZE)) {
        SLogError("KdsReqVerifyHmacSha256 invalid param size!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t hmacBuf[HMAC_LENGTH] = {0};
    DataBlob hmacResult = { hmacBuf, HMAC_LENGTH };
    const DataBlob msgBlob = { hukData->data1, hukData->data1Size };
    TEE_Result ret = HmacSha256(&msgBlob, keyData, &hmacResult);
    if (ret != TEE_SUCCESS) {
        SLogError("KdsReqVerifyHmacSha256 hmac failed!");
        return ret;
    }
    if (hmacResult.len != hukData->data2Size) {
        SLogError("KdsReqVerifyHmacSha256 hmacResult length error!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int32_t result = TEE_MemCompare(hmacResult.dataPtr, hukData->data2, hmacResult.len);
    if (result != TEE_SUCCESS) {
        SLogError("KdsReqVerifyHmacSha256 verify failed!");
        return KDS_ERROR_MAC_VERIFY_FAIL;
    }
    SLogTrace("KdsReqVerifyHmacSha256 verify success!");
    return TEE_SUCCESS;
}

// Do encrypt decrypt and hmac.
static TEE_Result KdsDataProcess(const DataBlob *keyData, uint32_t reqType,
    KdsHukDataInfos *hukData, KdsHukDataInfos *outData)
{
    if (keyData->dataPtr == NULL || keyData->len == 0) {
        SLogError("Bad Parameters!");
        return KDS_ERROR_BAD_PARAMETERS;
    }
    switch (reqType) {
        case KDS_REQ_ENCRYPT_AES_CBC_128:
        case KDS_REQ_ENCRYPT_AES_CBC_256:
            return KdsReqEncryptAesCbc(keyData, hukData, outData);
        case KDS_REQ_DECRYPT_AES_CBC_128:
        case KDS_REQ_DECRYPT_AES_CBC_256:
            return KdsReqDecryptAesCbc(keyData, hukData, outData);
        case KDS_REQ_HASH_GENERATE_HMAC_SHA256:
            return KdsReqGenHmacSha256(keyData, hukData, outData);
        case KDS_REQ_HASH_VERIFY_HMAC_SHA256:
            return KdsReqVerifyHmacSha256(keyData, hukData);
        default:
            SLogError("Unknown reqType: %x", reqType);
            return TEE_ERROR_BAD_PARAMETERS;
    }
}

TEE_Result HandleCaCommandReq(uint32_t paramTypes, TEE_Param *params)
{
    TEE_Result ret = ParamCheckCA(paramTypes, params);
    if (ret != TEE_SUCCESS) {
        SLogError("paramtypeCheck invalid paramtypes %x\n", ret);
        return ret;
    }

    KdsHukReqInfos *hukReqInfo = (KdsHukReqInfos *)params[INDEX_ZERO].memref.buffer;
    KdsHukDataInfos *hukDataInfo = (KdsHukDataInfos *)params[INDEX_ONE].memref.buffer;
    KdsHukDataInfos *out = (KdsHukDataInfos *)params[INDEX_THREE].memref.buffer;

    ret = KdsAuthCheck((char *)params[INDEX_TWO].memref.buffer,
        params[INDEX_TWO].memref.size, hukReqInfo);
    if (ret != TEE_SUCCESS) {
        SLogError("KdsAuthCheck failed: 0x%x", ret);
        return ret;
    }

    uint8_t mainKey[MAIN_KEY_LENGTH] = {0};
    ret = KdsDeriveDeviceKey(MAIN_KEY_LENGTH, mainKey);
    if (ret != TEE_SUCCESS) {
        SLogError("DeriveDeviceKey failed");
        return ret;
    }

    uint8_t hmacData[HMAC_LENGTH] = {0};
    DataBlob hmacResult = { hmacData, HMAC_LENGTH };
    DataBlob mkBlob = { mainKey, MAIN_KEY_LENGTH };
    ret = KdsGenerateReqkey(&mkBlob, hukReqInfo, &hmacResult);
    memset_s(mainKey, MAIN_KEY_LENGTH, 0, MAIN_KEY_LENGTH);
    if (ret != TEE_SUCCESS) {
        SLogError("KdsGenerateReqkey failed");
        return ret;
    }

    ret = KdsDataProcess(&hmacResult, hukReqInfo->reqType, hukDataInfo, out);
    memset_s(hmacData, HMAC_LENGTH, 0, HMAC_LENGTH);
    if (ret != TEE_SUCCESS) {
        SLogError("data process return :%x\n", ret);
    }
    return ret;
}