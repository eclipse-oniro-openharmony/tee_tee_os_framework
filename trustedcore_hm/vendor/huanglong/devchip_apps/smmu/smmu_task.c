/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: SMMU TA
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "hi_tee_hal.h"
#include "hi_tee_errno.h"
#include "securec.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_mem.h"
#include "smmu_struct.h"
#include "pthread.h"
#include "ta_framework.h"
#include "msg_ops.h"

#ifndef TA_SMMU_AGENT_SUSPEND
#define TA_SMMU_AGENT_SUSPEND       0xFFFE
#endif

typedef enum {
    HI_SECSMMU_SET = 0x2000,
    HI_SECSMMU_CLR,
    HI_SECSMMU_AGENT_CLOSED,
    HI_SECSMMU_MEM_PROC,
    HI_SECSMMU_COMMON_CHANNEL = 0x3000, /* the branch for testcase of smmu interface    */
    HI_SECSMMU_COMMON_AGENT_SUSPEND = 0x3001,
    HI_SECSMMU_COMMON_AGENT_RESUME = 0x3002,
} SMMU_COMMANDID;
#define MAX_AGENT_CONTENT_LENGHT  128
struct hi_tee_hal_agent_msg {
    unsigned int agent_id;
    unsigned int agent_pid;
    char agent_content[MAX_AGENT_CONTENT_LENGHT];
};
static UINT32 g_taskpid = 0;
static struct hi_tee_hal_agent_msg g_agentMsg = {0};
#define TEE_PARAM_LENGTH 4

static int tee_drv_agent_call(unsigned int agent_id, void *buffer, unsigned int len)
{
    void *internal_buf = NULL;
    unsigned internal_buf_len;
    int res;

    if (obtain_agent_work_lock(agent_id) != TEE_SUCCESS) {
        SMMU_LOG_ERROR("get obtain_agent_work_lock failed\n");
        return -1;
    }

    res = TEE_EXT_GetAgentBuffer(agent_id, &internal_buf, &internal_buf_len);
    if (res) {
        SMMU_LOG_ERROR("get AgentBuffer[0x%x] failed\n", agent_id);
        goto exit;
    }

    if (len > internal_buf_len) {
        SMMU_LOG_ERROR("%s buffer_len:0x%x exceeds the internal buffer 0x%x\n", __func__, len, internal_buf_len);
        goto exit;
    }

    res = memcpy_s(internal_buf, internal_buf_len, buffer, len);
    if (res) {
        SMMU_LOG_ERROR("memcpy failed\n");
        goto exit;
    }

    //res = TEE_EXT_SendAgentRequest(agent_id);
    //if (res) {
    //    SMMU_LOG_ERROR("sendAgentRequest failed, agent_id:0x%x \n", agent_id);
    //    goto exit;
    //}

    /* copy the result back the caller */
    res = memcpy_s(buffer, len, internal_buf, len);
    if (res) {
        SMMU_LOG_ERROR("memcpy failed\n");
        goto exit;
    }

exit:
    agent_work_unlock(agent_id);
    return res;
}

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    ret = AddCaller_CA_exec((char *)"hisi_teesmmu", 0);
    if (ret != TEE_SUCCESS) {
        SMMU_LOG_ERROR("AddCaller error %d\n", ret);
        tloge("AddCaller error %d\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec((char *)"./st_mem", 0);
    if (ret != TEE_SUCCESS) {
        SMMU_LOG_ERROR("AddCaller error %d\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec((char *)"hisi_teesmmu_agent_init", 0);
    if (ret != TEE_SUCCESS) {
        SMMU_LOG_ERROR("AddCaller error %d\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[TEE_PARAM_LENGTH],
                                              void** sessionContext)
{
    (void)paramTypes;
    (void)params;
    (void)sessionContext;

    return TEE_SUCCESS;
}

static TEE_Result smmu_ta_proc(unsigned int cmd_id, unsigned int cmd,
                               unsigned long long phys, unsigned long long size)
{
    struct hi_tee_smmu_ioctl_data buf_para = {0};
    unsigned int args[2] = {0}; /* 2 */

    buf_para.cmd = (unsigned long long)cmd;
    buf_para.cmd_id = cmd_id;
    buf_para.arg0 = buf_para.buf_phys = phys;
    buf_para.arg1 = buf_para.buf_size = size;
    args[0] = (unsigned int)&buf_para;
    args[1] = sizeof(struct hi_tee_smmu_ioctl_data);
    return hm_drv_call(HI_TEE_SYSCALL_SMMU_ID, args, ARRAY_SIZE(args));
}

static TEE_Result smmu_ta_resume(unsigned int paramTypes)
{
    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_VALUE_INPUT) &&
        (TEE_PARAM_TYPE_GET(paramTypes, 1) == TEE_PARAM_TYPE_VALUE_INPUT)) {
        unsigned int msgid;
        unsigned int buffLen = sizeof(struct hi_tee_hal_agent_msg);
        int ret = __SRE_TaskSelf(&g_taskpid);
        ret = smmu_ta_proc(HI_SECSMMU_COMMON_AGENT_RESUME, HI_SECSMMU_COMMON_AGENT_RESUME, g_taskpid, 0);
        if (ret) {
            SMMU_LOG_ERROR("\n HI_SECSMMU_COMMON_AGENT failed! \n");
            return ret;
        }

        while (1) {
            memset_s(&g_agentMsg, buffLen, 0, buffLen);
            ret = __SRE_MsgRcv(OS_WAIT_FOREVER, (void *)&msgid, (void *)&g_agentMsg, buffLen);
            if (msgid == TA_SMMU_AGENT_SUSPEND) {
                break;
            } else if (msgid == TA_CALL_AGENT) {
                tee_drv_agent_call(g_agentMsg.agent_id, g_agentMsg.agent_content,
                                   buffLen - 2 * sizeof(unsigned int)); // 2 for two unsigned int
                __SRE_MsgSnd(TA_CALL_AGENT, g_agentMsg.agent_pid, (void *)&g_agentMsg, buffLen);
            }
        }
        g_taskpid = 0;
        return TEE_SUCCESS;
    }

    return TEE_ERROR_GENERIC;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(void* session_context, unsigned int cmd_id,
                                                unsigned int paramTypes, TEE_Param params[TEE_PARAM_LENGTH])
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    unsigned long long buf_phy, buf_size;

    (void)session_context;
    buf_phy = (unsigned long long)(params[0].value.a | ((unsigned long long)params[0].value.b << 32)); /* 32 high */
    buf_size = (unsigned long long)params[1].value.a;

    switch (cmd_id) {
        case HI_SECSMMU_SET:
        case HI_SECSMMU_CLR:
            if (TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) {
                SMMU_LOG_ERROR("The paramTypes is not correctly!\n");
                return TEE_ERROR_GENERIC;
            }
            if (cmd_id == HI_SECSMMU_SET)
                ret = smmu_ta_proc(HISI_SEC_MAPTOSMMU_AND_SETFLAG, 0, buf_phy, buf_size);
            else
                ret = smmu_ta_proc(HISI_SEC_UNMAPFROMSMMU_AND_CLRFLG, 0, buf_phy, buf_size);
            break;
        case HI_SECSMMU_AGENT_CLOSED:
            ret = smmu_ta_proc(AGENT_CLOSED, 0, 0, 0);
            break;
        case HI_SECSMMU_MEM_PROC:
            ret = smmu_ta_proc(SEC_IOCTL, HI_SECSMMU_MEM_PROC, 0, 0);
            break;
        case HI_SECSMMU_COMMON_CHANNEL:
            if ((TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_NSSMMU_HAND_INPUT) ||
                (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_SECSMMU_HAND_INPUT) ||
                (TEE_PARAM_TYPE_GET(paramTypes, 0) == TEE_PARAM_TYPE_PHYS_HAND_INPUT))
                ret = smmu_ta_proc(SEC_IOCTL, params[1].value.a, buf_phy, params[1].value.b);
            else
                ret = smmu_ta_proc(SEC_IOCTL, params[0].value.a, params[0].value.b, params[1].value.a);
            break;
        case HI_SECSMMU_COMMON_AGENT_SUSPEND:
            ret = smmu_ta_proc(HI_SECSMMU_COMMON_AGENT_SUSPEND, HI_SECSMMU_COMMON_AGENT_SUSPEND, g_taskpid, 1);
            ret = TEE_SUCCESS;
            break;
        case HI_SECSMMU_COMMON_AGENT_RESUME:
            ret = smmu_ta_resume(paramTypes);
            break;
        default:
            SMMU_LOG_ERROR("Invalid TA invoke command, cmd = %d!\n", cmd_id);
    }

    if (ret != TEE_SUCCESS)
        SMMU_LOG_ERROR("TA Invoke command falied, cmd_id = %d ret = 0x%x!\n", cmd_id, ret);

    return ret;
}

__DEFAULT void TA_CloseSessionEntryPoint(void* session_context)
{
    (void)session_context;
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
}
