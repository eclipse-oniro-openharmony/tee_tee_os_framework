/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: added for hm-teeos
 * Author: hanxuanwei
 * Create: 2018-05-21
 */

#include "tee_ext_api.h"
#include "hi_vcodec_task.h"

static TEE_Result TaVdecInit(uint32_t paramTypes, TEE_Param params[4])
{
    if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_ION_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_ION_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    PHY_ADDR_INFO_S addrInfo = {0};
    addrInfo.hal_phyaddr = (uint32_t)(uintptr_t)params[1].memref.buffer;
    addrInfo.share_phyaddr = (uint32_t)(uintptr_t)params[2].memref.buffer;

    params[3].value.a = (unsigned int)__SEC_VDEC_Init((uint32_t *)params[0].memref.buffer, params[0].memref.size,
                                                      (uint32_t *)(&addrInfo), sizeof(PHY_ADDR_INFO_S));
    return TEE_SUCCESS;
}

static TEE_Result TaVdecExit(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[3].value.a = (unsigned int)__SEC_VDEC_Exit(params[0].value.a);

    return TEE_SUCCESS;
}

static TEE_Result TaVdecSuspend(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        tloge("parameter type check failed , %d\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_Suspend();

    return TEE_SUCCESS;
}

static TEE_Result TaVdecResume(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INPUT)) { /*lint !e845*/
        tloge("parameter type check failed , %d\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[0].value.a = (unsigned int)__SEC_VDEC_Resume();

    return TEE_SUCCESS;
}

static TEE_Result TaVdecControl(uint32_t paramTypes, TEE_Param params[4])
{
    PHY_ADDR_INFO_S addrInfo = {0};
    int32_t chanId;
    uint32_t commandId;

    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (((SEC_CONTROL_PARAM_S *)params[0].memref.buffer)->value.a != HI_VCODEC_INVOKE_CODE_A ||
            ((SEC_CONTROL_PARAM_S *)params[0].memref.buffer)->value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    chanId = ((SEC_CONTROL_PARAM_S *)params[0].memref.buffer)->chanID;
    commandId = ((SEC_CONTROL_PARAM_S *)params[0].memref.buffer)->cmdID;

    if (TEE_PARAM_TYPE_GET(paramTypes, 2) == TEE_PARAM_TYPE_ION_INPUT) {
        if (commandId == 51) { // VDEC_CID_BIND_MEM_TO_CHANNEL 51 alloc seperate mem and bind to vfmw
            addrInfo.pmv_phyaddr = (uint32_t)(uintptr_t)params[2].memref.buffer;
        } else {
            addrInfo.scd_phyaddr = (uint32_t)(uintptr_t)params[2].memref.buffer;
        }
    }

    if (TEE_PARAM_TYPE_GET(paramTypes, 3) == TEE_PARAM_TYPE_ION_INPUT) {
        addrInfo.ctx_phyaddr = (uint32_t)(uintptr_t)params[3].memref.buffer;
    }

    if (TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_MEMREF_INOUT) {
        ((SEC_CONTROL_PARAM_S *)params[0].memref.buffer)->value.a = __SEC_VDEC_Control(chanId, commandId,
                                                                                       params[1].memref.buffer,
                                                                                       params[1].memref.size,
                                                                                       (uint32_t *)(&addrInfo),
                                                                                       sizeof(PHY_ADDR_INFO_S));
    } else if (TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_NONE) {
        ((SEC_CONTROL_PARAM_S *)params[0].memref.buffer)->value.a = __SEC_VDEC_Control(chanId, commandId, NULL, 0,
                                                                                       (uint32_t *)(&addrInfo),
                                                                                       sizeof(PHY_ADDR_INFO_S));
    } else {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result TaVdecRunProcess(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_NONE) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[3].value.a = (unsigned int)__SEC_VDEC_RunProcess(0, 0);  // these parameters not used

    return TEE_SUCCESS;
}

static TEE_Result  TaVdecGetChanImage(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INOUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[3].value.a =
        (unsigned int)__SEC_VDEC_GetChanImage((int)params[0].value.a, (unsigned int *)params[1].memref.buffer);

    return TEE_SUCCESS;
}

static TEE_Result TaVdecReleaseChanImage(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[3].value.a =
        (unsigned int)__SEC_VDEC_ReleaseChanImage((int)params[0].value.a, (unsigned int *)params[1].memref.buffer);

    return TEE_SUCCESS;
}

static TEE_Result TaVdecConfigInputBuffer(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_ION_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        tloge("[%d]: parameter is error\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    PHY_ADDR_INFO_S addrInfo = {0};
    addrInfo.input_phyaddr = (uint32_t)(uintptr_t)params[1].memref.buffer;
    params[3].value.a =
        (unsigned int)__SEC_VDEC_ConfigInputBuffer((int)params[0].value.a, (unsigned int *)(&addrInfo));

    return TEE_SUCCESS;
}

TEE_Result TaVencMemAssignment(uint32_t paramTypes, TEE_Param params[4])
{
    if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_ION_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT) &&
        !check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_ION_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("[%d]: parameter is error\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t secShareFd = (uint32_t)(uintptr_t)params[1].memref.buffer;
    uint32_t ionSize = params[1].memref.size;
    uint32_t offset = params[2].value.a; // params 2 if offet of fd
    uint32_t direct = params[3].value.a; // 1: tee2ree, 0: ree2tee
    uint32_t datalen = direct ? params[0].value.a : params[0].memref.size;
    tlogd("ionSize:%d, datalen: %d,secShareFd:%d,direct:%d offset:%d", ionSize, datalen, secShareFd, direct, offset);
    if (ionSize < offset || ionSize - offset < datalen) {
        tloge("ionSize:%d, offset:%d", ionSize, offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (direct == 1) { // tee2ree
        if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT || datalen != NAL_HEAD_LEN) {
            tloge("[%d]: parameter is error nalLen %d", __LINE__, datalen);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        struct NalHead nalHead = {0};
        __SEC_VENC_MEMTEE2REE((uint32_t)(uintptr_t)(&nalHead), secShareFd, offset, datalen);
        if (nalHead.invalidBytes >= NAL_HEAD_LEN || nalHead.packetLen < NAL_HEAD_LEN + nalHead.invalidBytes) {
            tloge("invalid bytes %d or packet length %d error", nalHead.invalidBytes, nalHead.packetLen);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        params[0].value.a = nalHead.packetLen - NAL_HEAD_LEN - nalHead.invalidBytes;
        return TEE_SUCCESS;
    }
    // ree2tee
    if (datalen > MAX_COPY_SIZE) { // max headlen SPS(300), VPS(300), PPS(300), (SEI 320)
        tloge("datalen:%d is out of max size", datalen);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    void *norPhyAddr = params[0].memref.buffer;
    __SEC_VENC_MEMREE2TEE((uint32_t)(uintptr_t)norPhyAddr, secShareFd, offset, datalen);
    return TEE_SUCCESS;
}

#ifdef VCODEC_ENG_VERSION
TEE_Result TaVencMemCpyForTest(uint32_t paramTypes, TEE_Param params[4])
{
    if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_ION_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT) &&
        !check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_ION_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("[%d]: parameter is error\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    void *norPhyAddr = params[0].memref.buffer;
    int datalen = params[0].memref.size;
    uint32_t secShareFd = (uint32_t)(uintptr_t)params[1].memref.buffer;
    int ionSize = params[1].memref.size;
    int offset = params[2].value.a;
    int direct = params[3].value.a; // direct 0 : from ree to tee copy  1 : from tee to ree copy
    if (ionSize < datalen) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("datalen: %d,secShareFd:%d,direct:%d \n", datalen, secShareFd, direct);
    if (direct) {
        __SEC_VENC_MEMTEE2REE((uint32_t)(uintptr_t)norPhyAddr, secShareFd, (uint32_t)offset, (uint32_t)datalen);
    } else {
        __SEC_VENC_MEMREE2TEE((uint32_t)(uintptr_t)norPhyAddr, secShareFd, (uint32_t)offset, (uint32_t)datalen);
    }
    return TEE_SUCCESS;
}
#endif

TEE_Result TaVencCfgMaster(uint32_t paramTypes, TEE_Param param[4])
{
    if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
        tloge("[%d]: parameter is error\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t secVencState = param[0].value.a; // 0: off, 1:on
    uint32_t coreId = param[0].value.b; // 0: venc0, 1: venc1
    if (secVencState > 1 || coreId > 1) { // soc max venc num is 2
        tloge("[%d]: parameter is error\n", __LINE__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    __SEC_VENC_CFG_MASTER(secVencState, coreId);
    return TEE_SUCCESS;
}

#ifdef VCODEC_ENG_VERSION
static TEE_Result TaVdecReadProc(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[3].value.a = (unsigned int)__SEC_VDEC_ReadProc(params[0].value.a, params[0].value.b, (int)params[1].value.a);

    return TEE_SUCCESS;
}

static TEE_Result TaVdecWriteProc(uint32_t paramTypes, TEE_Param params[4])
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[3].value.a != HI_VCODEC_INVOKE_CODE_A || params[3].value.b != HI_VCODEC_INVOKE_CODE_B) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params[3].value.a = (unsigned int)__SEC_VDEC_WriteProc(params[0].value.a, (int)params[0].value.b);

    return TEE_SUCCESS;
}
#endif

__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(const void *sessionContext,
    uint32_t commandId, uint32_t paramTypes, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    S_VAR_NOT_USED(sessionContext);

    switch (commandId) {
        case HIVCODEC_CMD_ID_INIT:
            ret = TaVdecInit(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_EXIT:
            ret = TaVdecExit(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_SUSPEND:
            ret = TaVdecSuspend(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_RESUME:
            ret = TaVdecResume(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_CONTROL:
            ret = TaVdecControl(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_RUN_PROCESS:
            ret = TaVdecRunProcess(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_GET_IMAGE:
            ret = TaVdecGetChanImage(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_RELEASE_IMAGE:
            ret = TaVdecReleaseChanImage(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_CONFIG_INPUT_BUFFER:
            ret = TaVdecConfigInputBuffer(paramTypes, params);
            break;

#ifdef VCODEC_ENG_VERSION
        case HIVCODEC_CMD_ID_READ_PROC:
            ret = TaVdecReadProc(paramTypes, params);
            break;

        case HIVCODEC_CMD_ID_WRITE_PROC:
            ret = TaVdecWriteProc(paramTypes, params);
            break;
#endif
        case HIVCODEC_CMD_ID_MEM_CPY:
            ret = TaVencMemAssignment(paramTypes, params);
            break;
        case HIVCODEC_CMD_ID_CFG_MASTER:
            ret = TaVencCfgMaster(paramTypes, params);
            break;
#ifdef VCODEC_ENG_VERSION
        case HIVCODEC_CMD_ID_MEM_CPY_PROC:
            ret = TaVencMemCpyForTest(paramTypes, params);
            break;
#endif
        default:
            ret = TEE_ERROR_BAD_PARAMETERS;
            tlogd("HiVCodec: unkown cmd %d invoked!\n", commandId);
            break;
    }

    return  ret;
}

__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    ret = AddCaller_CA_exec(CLIENT_CA_VDECODER, VDECODER_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CLIENT_CA_VDECODER, MEDIA_CODEC_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(MEDIASERVER_NAME, MEDIA_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }
    ret = AddCaller_CA_exec(MEDIADRMSERVER_NAME, MEDIA_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CLIENT_CA_MEDIACODEC, MEDIA_CODEC_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CLIENT_CA_MEDIACODEC, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }

#ifdef VCODEC_ENG_VERSION
    ret = AddCaller_CA_exec(SAMPLE_OMXVDEC_NAME, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }
    ret = AddCaller_CA_exec(SAMPLE_OMXVENC_NAME, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        tlogd("%d, add failed, ret = %d\n", __LINE__, ret);
        return ret;
    }
#endif

    return ret;
}

__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[4], const void **sessionContext)
{
    S_VAR_NOT_USED(params);
    S_VAR_NOT_USED(sessionContext);

    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_NONE) || /*lint !e835*/
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_MEMREF_INPUT)) { /*lint !e845*/
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(const void *sessionContext)
{
    S_VAR_NOT_USED(sessionContext);
}

__attribute__((visibility ("default"))) void TA_DestroyEntryPoint(void)
{
}
