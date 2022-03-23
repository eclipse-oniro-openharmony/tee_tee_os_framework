/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Deal with kds phase three command.
 * Create: 2020-06-28
 */

#include "kds_phase3.h"
#include "tee_mem_mgmt_api.h"
#include "kds_defs.h"
#include "kds_core.h"

static TEE_Result ParamTypeCheckTAFromCA(uint32_t paramTypes, const TEE_Param *params)
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, INDEX_ZERO) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, INDEX_ONE) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, INDEX_TWO) != TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, INDEX_THREE) != TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types.");
        return TEE_ERROR_BAD_FORMAT;
    }

    if (params[INDEX_ZERO].memref.size != sizeof(KdsGidReqInfo)) {
        SLogError("param 0 size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[INDEX_ONE].memref.size != sizeof(KdsGidDataInfos)) {
        SLogError("param 1 size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[INDEX_ONE].memref.buffer == NULL) {
        SLogError("gidSourceData is null");
        return TEE_FAIL;
    }

    if (params[INDEX_TWO].memref.size != sizeof(KdsGidResultInfo)) {
        SLogError("out plain size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result CheckGidSourceData(const KdsGidDataInfos *gidSourceData)
{
    if ((gidSourceData->tmpPkSize == 0) || (gidSourceData->tmpPkSize > TMP_PK_SIZE) ||
        (gidSourceData->nonceSize == 0) || (gidSourceData->nonceSize > NONCE_SIZE) ||
        (gidSourceData->aadSize == 0) || (gidSourceData->aadSize > AAD_SIZE) ||
        (gidSourceData->cipherSize == 0) || (gidSourceData->cipherSize > CIPHER_SIZE) ||
        (gidSourceData->custmizedInfoSize == 0) ||
        (gidSourceData->custmizedInfoSize > CUSTMIZED_INFO_SIZE) ||
        (gidSourceData->metadataSize == 0) || (gidSourceData->metadataSize > METADATA_SIZE) ||
        (gidSourceData->processInfoSize == 0) ||
        (gidSourceData->processInfoSize > PROCESSINFO_SIZE)) {
        SLogError("gidSourceData sub premeters size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (gidSourceData->tagSize != TAG_SIZE) {
        SLogError("source tag size error");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result AssignGidDecryptParam(KdsGidDataInfos *gidSourceData,
    KdsDecryptParams *decryptParams)
{
    decryptParams->aadData.dataPtr = gidSourceData->aad;
    decryptParams->aadData.len = gidSourceData->aadSize;

    decryptParams->pubKey.dataPtr = gidSourceData->tmpPk;
    decryptParams->pubKey.len = gidSourceData->tmpPkSize / DIVISION_NUM_TWO;

    decryptParams->cipherData.dataPtr = gidSourceData->cipher;
    decryptParams->cipherData.len = gidSourceData->cipherSize;

    decryptParams->nonceData.len = gidSourceData->nonceSize;
    decryptParams->nonceData.dataPtr = gidSourceData->nonce;

    decryptParams->tagData.len = gidSourceData->tagSize;
    decryptParams->tagData.dataPtr = gidSourceData->tag;

    decryptParams->extInfo.len = gidSourceData->processInfoSize;
    decryptParams->extInfo.dataPtr = gidSourceData->processInfo;

    int ret = memcpy_s(decryptParams->customData.dataPtr,
        PROC_NAME_LEN * sizeof(char) + CUSTMIZED_INFO_SIZE,
        ((ProcessMetadata *)(gidSourceData->metadata))->procName, PROC_NAME_LEN * sizeof(char));
    if (ret != EOK) {
        SLogError("AssignGidDecryptParam copy process name failed.");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    ret = memcpy_s(decryptParams->customData.dataPtr + PROC_NAME_LEN * sizeof(char),
        CUSTMIZED_INFO_SIZE,
        gidSourceData->custmizedInfo, gidSourceData->custmizedInfoSize);
    decryptParams->customData.len = PROC_NAME_LEN * sizeof(char) + gidSourceData->custmizedInfoSize;
    if (ret != EOK) {
        SLogError("AssignGidDecryptParam copy custom info failed.");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    return TEE_SUCCESS;
}

static TEE_Result DealGidOutData(const DataBlob *out, const KdsGidDataInfos *gidSourceData,
    TEE_Param *params, uint32_t plainLen)
{
    uint32_t sizeCount = sizeof(uint32_t); // Used for solving hisi online warnings.
    int ret = memcpy_s(params[INDEX_TWO].memref.buffer,
        params[INDEX_TWO].memref.size,
        &plainLen,
        sizeCount);
    if (ret != EOK) {
        SLogError("DealGidOutData copy plainLen failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = memcpy_s(params[INDEX_TWO].memref.buffer + sizeCount,
        params[INDEX_TWO].memref.size - sizeCount,
        &gidSourceData->processInfoSize,
        sizeCount);
    if (ret != EOK) {
        SLogError("DealGidOutData copy processInfoSize failed.");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = memcpy_s(params[INDEX_TWO].memref.buffer + sizeCount + sizeCount,
        params[INDEX_TWO].memref.size - sizeCount - sizeCount,
        out->dataPtr,
        RESULT_SIZE * sizeof(uint8_t));
    if (ret != EOK) {
        SLogError("DealGidOutData copy out data failed.");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = memcpy_s(params[INDEX_TWO].memref.buffer + sizeCount + sizeCount +
        (RESULT_SIZE * sizeof(uint8_t)),
        params[INDEX_TWO].memref.size - sizeCount - sizeCount - (RESULT_SIZE * sizeof(uint8_t)),
        gidSourceData->processInfo,
        gidSourceData->processInfoSize);
    if (ret != EOK) {
        SLogError("DealGidOutData copy processInfo failed.");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    return TEE_SUCCESS;
}

TEE_Result HandleGidCommandFromCa(uint32_t paramTypes, TEE_Param *params)
{
    TEE_Result ret = ParamTypeCheckTAFromCA(paramTypes, params);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    KdsGidDataInfos *gidSourceData = (KdsGidDataInfos *)(params[INDEX_ONE].memref.buffer);
    if (CheckGidSourceData(gidSourceData) != TEE_SUCCESS) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t customInfo[PROC_NAME_LEN * sizeof(char) + CUSTMIZED_INFO_SIZE] = {0};
    KdsDecryptParams decryptParams = KDS_DECRYPT_PARAMS_INIT_VALUE;
    decryptParams.customData.dataPtr = customInfo;

    if (AssignGidDecryptParam(gidSourceData, &decryptParams) != TEE_SUCCESS) {
        memset_s(customInfo, sizeof(customInfo), 0, sizeof(customInfo));
        SLogError("AssignGidDecryptParam failed.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    DataBlob out = { NULL, sizeof(KdsGidResultInfo) };
    out.dataPtr = (uint8_t *)TEE_Malloc(sizeof(KdsGidResultInfo), 0);
    if (out.dataPtr == NULL) {
        memset_s(customInfo, sizeof(customInfo), 0, sizeof(customInfo));
        SLogError("TEE_Malloc failed.");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = KdsDecryptService(&decryptParams, &out);
    memset_s(customInfo, sizeof(customInfo), 0, sizeof(customInfo));
    if (ret != TEE_SUCCESS) {
        SLogError("decrypt, failed %x\n", ret);
    } else {
        ret = DealGidOutData(&out, gidSourceData, params,
            (uint32_t)(decryptParams.cipherData.len - decryptParams.tagData.len));
        if (ret != TEE_SUCCESS) {
            SLogError("DealGidOutData, failed %x\n", ret);
        }
    }

    memset_s(out.dataPtr, out.len, 0, out.len);
    FREE_DATA_BLOB(&out);
    return ret;
}