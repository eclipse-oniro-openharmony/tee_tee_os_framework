/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Deal with kds phase one command.
 * Create: 2020-06-28
 */

#include "kds_phase1.h"
#include "tee_mem_mgmt_api.h"
#include "kds_defs.h"
#include "kds_core.h"

static TEE_Result ParamSizeCheckTA(const TEE_Param *params)
{
    if ((params[INDEX_ZERO].memref.size < TA_PARAM_ONE_SIZE) ||
        (params[INDEX_ZERO].memref.buffer == NULL)) {
        SLogError("invalid param, param[0]");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((params[INDEX_ONE].memref.size < TA_PARAM_TWO_SIZE) ||
        (params[INDEX_ONE].memref.buffer == NULL)) {
        SLogError("invalid param, param[1]");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((params[INDEX_TWO].memref.size < TA_PARAM_THREE_SIZE) ||
        (params[INDEX_TWO].memref.buffer == NULL)) {
        SLogError("invalid param, param[2]");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((params[INDEX_THREE].memref.size == 0) || (params[INDEX_THREE].memref.buffer == NULL)) {
        SLogError("invalid param, param[3]");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result ParamCheckTA(uint32_t paramTypes, const TEE_Param *params)
{
    if (TEE_PARAM_TYPE_GET(paramTypes, INDEX_ZERO) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(paramTypes, INDEX_ONE) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(paramTypes, INDEX_TWO) != TEE_PARAM_TYPE_MEMREF_INPUT ||
        TEE_PARAM_TYPE_GET(paramTypes, INDEX_THREE) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
        SLogError("Bad expected parameter types.");
        return TEE_ERROR_BAD_FORMAT;
    }

    return ParamSizeCheckTA(params);
}

static TEE_Result ParseParamIndexZero(TEE_Param *params, KdsDecryptParams *decryptParams)
{
    uint32_t ptrOffSet = 0;
    const uint32_t paramZeroSize = params[INDEX_ZERO].memref.size;
    uint8_t *paramZero = params[INDEX_ZERO].memref.buffer;
    decryptParams->nonceData.len = *((size_t *)paramZero);
    ptrOffSet += sizeof(uint32_t);
    decryptParams->aadData.len = *((size_t *)(paramZero + ptrOffSet));
    ptrOffSet += sizeof(uint32_t);
    decryptParams->tagData.len = *((size_t *)(paramZero + ptrOffSet));
    ptrOffSet += sizeof(uint32_t);
    decryptParams->cipherData.len = *((size_t *)(paramZero + ptrOffSet));
    ptrOffSet += sizeof(uint32_t);

    if ((decryptParams->nonceData.len != AES_CCM_NONCE_SIZE) || (decryptParams->aadData.len != AAD_SIZE) ||
        (decryptParams->tagData.len != TAG_SIZE) || (decryptParams->cipherData.len > MAX_CIPHER_SIZE)) {
        SLogError("ParseParamIndexZero len error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (paramZeroSize != (PARAM_ZERO_UINT32_COUNT * sizeof(uint32_t) + decryptParams->tagData.len +
        decryptParams->cipherData.len + decryptParams->aadData.len + decryptParams->nonceData.len)) {
        SLogError("param 0 size error paramZeroSize is 0x%x", paramZeroSize);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    decryptParams->nonceData.dataPtr = paramZero + ptrOffSet;
    ptrOffSet += decryptParams->nonceData.len;
    decryptParams->aadData.dataPtr = paramZero + ptrOffSet;
    ptrOffSet += decryptParams->aadData.len;
    decryptParams->tagData.dataPtr = paramZero + ptrOffSet;
    ptrOffSet += decryptParams->tagData.len;
    decryptParams->cipherData.dataPtr = paramZero + ptrOffSet;
    if ((decryptParams->nonceData.dataPtr == NULL) || (decryptParams->aadData.dataPtr == NULL) ||
        (decryptParams->tagData.dataPtr == NULL) || (decryptParams->cipherData.dataPtr == NULL)) {
        SLogError("ParseParamIndexZero dataptr is NULL");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result ParseParamIndexOne(TEE_Param *params, KdsDecryptParams *decryptParams)
{
    uint32_t ptrOffSet = 0;
    uint32_t paramOneSize = params[INDEX_ONE].memref.size;
    uint8_t *paramOne = params[INDEX_ONE].memref.buffer;

    decryptParams->customData.len = *((size_t *)paramOne);
    ptrOffSet += sizeof(uint32_t);
    decryptParams->extInfo.len = *((size_t *)(paramOne + ptrOffSet));
    ptrOffSet += sizeof(uint32_t);

    if ((decryptParams->customData.len != TA_CUASTOM_SIZE) ||
        (decryptParams->extInfo.len != EXT_INFO_SIZE)) {
        SLogError("ParseParamIndexOne len error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (paramOneSize != (decryptParams->customData.len + decryptParams->extInfo.len +
        PARAM_ONE_UINT32_COUNT * sizeof(uint32_t))) {
        SLogError("ParseParamIndexOne param 1 size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    decryptParams->customData.dataPtr = paramOne + ptrOffSet;
    ptrOffSet += decryptParams->customData.len;
    decryptParams->extInfo.dataPtr = paramOne + ptrOffSet;
    if ((decryptParams->customData.dataPtr == NULL) || (decryptParams->extInfo.dataPtr == NULL)) {
        SLogError("ParseParamIndexOne dataptr is NULL");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result ParseParamIndexTwo(TEE_Param *params, KdsDecryptParams *decryptParams)
{
    uint32_t ptrOffSet = 0;
    uint32_t paramTwoSize = params[INDEX_TWO].memref.size;
    uint8_t *paramTwo = params[INDEX_TWO].memref.buffer;

    decryptParams->pubKey.len = *((size_t *)paramTwo);
    ptrOffSet += sizeof(uint32_t);
    if (decryptParams->pubKey.len > TMP_PK_MAX) {
        SLogError("ParseParamIndexTwo pubkey size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (paramTwoSize != decryptParams->pubKey.len + sizeof(uint32_t) + sizeof(uint32_t)) {
        SLogError("ParseParamIndexTwo size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t curveInfo = *((size_t *)(paramTwo + ptrOffSet));
    if (curveInfo == CONST_CURVE_INFO) {
        SLogTrace("ParseParamIndexTwo curve info ok");
    }
    ptrOffSet += sizeof(uint32_t);

    decryptParams->pubKey.dataPtr = paramTwo + ptrOffSet;
    if (decryptParams->pubKey.dataPtr == NULL) {
        SLogError("ParseParamIndexTwo dataPtr NULL");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result AssignTaDecryptParam(TEE_Param *params, KdsDecryptParams *decryptParams)
{
    if (ParseParamIndexZero(params, decryptParams) != TEE_SUCCESS) {
        SLogError("ParseParamIndexZero, failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ParseParamIndexOne(params, decryptParams) != TEE_SUCCESS) {
        SLogError("ParseParamIndexOne, failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ParseParamIndexTwo(params, decryptParams) != TEE_SUCCESS) {
        SLogError("ParseParamIndexTwo, failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result ExtractRealUuid(const uint8_t *uuidOrigin, uint32_t originLen, uint8_t *uuid,
    uint32_t uuidLen)
{
    if (originLen != uuidLen) {
        SLogError("originLen not euqals uuidLen\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    int ret;
    for (uint32_t i = 0; i < sizeof(uint32_t); i++) {
        ret = memcpy_s(uuid + OFFSET_THREE - i, uuidLen - (OFFSET_THREE - i),
            uuidOrigin + i, sizeof(uint8_t));
        if (ret != EOK) {
            SLogError("copy uint32 failed, ret %x\n", ret);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    uint32_t offset = sizeof(uint32_t);
    for (uint32_t i = 0; i < sizeof(uint16_t); i++) {
        ret = memcpy_s(uuid + offset + OFFSET_ONE - i, uuidLen - (offset + OFFSET_ONE - i),
            uuidOrigin + offset + i, sizeof(uint8_t));
        if (ret != EOK) {
            SLogError("copy uint16 part one failed, ret %x\n", ret);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    offset += sizeof(uint16_t);
    for (uint32_t i = 0; i < sizeof(uint16_t); i++) {
        ret = memcpy_s(uuid + offset + OFFSET_ONE - i, uuidLen - (offset + OFFSET_ONE - i),
            uuidOrigin + offset + i,
            sizeof(uint8_t));
        if (ret != EOK) {
            SLogError("copy uint16 part two failed, ret %x\n", ret);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    offset += sizeof(uint16_t);
    ret = memcpy_s(uuid + offset, UUID_SIZE - offset, uuidOrigin + offset,
        (UUID_UINT8_COUNT * sizeof(uint8_t)));
    if (ret != EOK) {
        SLogError("copy uint8 failed, ret %x\n", ret);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result GetTaCallerUuid(uint8_t *uuid, uint32_t uuidLen)
{
    /* The caller_info struct is not defined in native space. */
    caller_info callerInfo;
    uint8_t uuidOrigin[UUID_SIZE] = {0};
    TEE_Result ret = TEE_EXT_GetCallerInfo(&callerInfo, sizeof(caller_info));
    if (ret != TEE_SUCCESS) {
        SLogError("GetTaCallerUuid TEE_EXT_GetCallerInfo failed, ret: %x", ret);
        return ret;
    }

    int err = memcpy_s(uuidOrigin, UUID_SIZE, &(callerInfo.caller_identity.caller_uuid),
        sizeof(callerInfo.caller_identity.caller_uuid));
    if (err != EOK) {
        SLogError("GetTaCallerUuid copy uuid failed");
        memset_s(uuidOrigin, UUID_SIZE, 0, UUID_SIZE);
        return TEE_FAIL;
    }

    ret = ExtractRealUuid(uuidOrigin, UUID_SIZE, uuid, uuidLen);
    memset_s(uuidOrigin, UUID_SIZE, 0, UUID_SIZE);
    if (ret != TEE_SUCCESS) {
        SLogError("ExtractRealUuid failed");
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result ConstructCustomWithUuid(DataBlob *taCustomDataPlusUuid,
    const KdsDecryptParams *decryptParams)
{
    uint8_t callerUuid[UUID_SIZE] = {0};
    TEE_Result ret = GetTaCallerUuid(callerUuid, UUID_SIZE);
    do {
        if (ret != TEE_SUCCESS) {
            SLogError("get ta caller uuid,failed %x\n", ret);
            break;
        }

        if (((UUID_SIZE + decryptParams->customData.len) > MAX_MALLOC_LEN) &&
            (decryptParams->customData.len > (KDS_UINT_MAX - UUID_SIZE))) {
            ret = TEE_ERROR_BAD_PARAMETERS;
            SLogError("uuid size or custom data size error");
            break;
        }
        int errCode = memcpy_s(taCustomDataPlusUuid->dataPtr, taCustomDataPlusUuid->len,
            callerUuid, UUID_SIZE);
        if (errCode != EOK) {
            ret = TEE_ERROR_BAD_PARAMETERS;
            break;
        }

        errCode = memcpy_s(taCustomDataPlusUuid->dataPtr + UUID_SIZE,
            taCustomDataPlusUuid->len - UUID_SIZE,
            decryptParams->customData.dataPtr,
            TA_CUASTOM_SIZE);
        if (errCode != EOK) {
            ret = TEE_ERROR_BAD_PARAMETERS;
            break;
        }
        ret = TEE_SUCCESS;
    } while (0);
    memset_s(callerUuid, UUID_SIZE, 0, UUID_SIZE);
    return ret;
}

TEE_Result HandleTaCommandDecrypt(uint32_t paramTypes, TEE_Param *params)
{
    TEE_Result ret = ParamCheckTA(paramTypes, params);
    if (ret != TEE_SUCCESS) {
        SLogError("ParamCheckTA failed");
        return ret;
    }

    KdsDecryptParams decryptParams = KDS_DECRYPT_PARAMS_INIT_VALUE;
    ret = AssignTaDecryptParam(params, &decryptParams);
    if (ret != TEE_SUCCESS) {
        SLogError("AssignTaDecryptParam failed");
        return ret;
    }

    DataBlob out;
    out.dataPtr = params[INDEX_THREE].memref.buffer;
    out.len = params[INDEX_THREE].memref.size;
    if (out.len != (decryptParams.cipherData.len - decryptParams.tagData.len)) {
        SLogError("plain size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t realCustomData[UUID_SIZE + TA_CUASTOM_SIZE] = {0};
    DataBlob taCustomDataPlusUuid = { realCustomData, UUID_SIZE + TA_CUASTOM_SIZE };
    ret = ConstructCustomWithUuid(&taCustomDataPlusUuid, &decryptParams);
    decryptParams.customData.dataPtr = taCustomDataPlusUuid.dataPtr;
    decryptParams.customData.len = taCustomDataPlusUuid.len;
    if (ret != TEE_SUCCESS) {
        SLogError("ConstructCustomWithUuid, failed %x\n", ret);
        memset_s(realCustomData, UUID_SIZE + TA_CUASTOM_SIZE, 0, UUID_SIZE + TA_CUASTOM_SIZE);
        return ret;
    }

    ret = KdsDecryptService(&decryptParams, &out);
    memset_s(realCustomData, UUID_SIZE + TA_CUASTOM_SIZE, 0, UUID_SIZE + TA_CUASTOM_SIZE);
    if (ret != TEE_SUCCESS) {
        SLogError("decrypt, failed %x\n", ret);
        return ret;
    }
    return ret;
}