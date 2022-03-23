/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: msp ta channel, ta commands callback function table,
 *              call different test interfaces
 * Create: 2020-10-27
 */
#include "msp_ta_channel.h"
#include <drv_module.h>
#include "drv_param_type.h"
#include <pthread.h>
#include <securec.h>
#include <sre_syscalls_id_ext.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <string.h>
#include <hmdrv_stub.h>
#include <tee_log.h>

#define MAX_MSPT_CB_NUM 15
#define MAX_MSPT_ECALL_FUNC_NUM 10
#define MAX_MSPT_COMMON_PROC_NUM 5
#define MAX_MSPT_FUNC_CHAR_SIZE 20

static pthread_mutex_t g_msp_chan_mutex;
static uint32_t g_mspt_cproc_cur_num;
static uint32_t g_mspt_efunc_cur_num;
static uint32_t g_mspt_cb_cur_num;
struct common_test_func_s {
    uint32_t (*proc_func)(const struct msp_chan_parms *chan_parms, char *iodata);
    char cproc_name[MAX_MSPT_FUNC_CHAR_SIZE];
};

struct ecall_func_s {
    uint32_t (*ecall_func)(const struct msp_chan_parms *chan_parms);
    char efunc_name[MAX_MSPT_FUNC_CHAR_SIZE];
};

struct msp_chan_cb_s {
    uint32_t cmd;
    uint32_t (*cb_func)(char *iodata, const struct msp_chan_parms *chan_parms);
};

static struct common_test_func_s g_common_test_func_tbl[MAX_MSPT_COMMON_PROC_NUM];
static struct ecall_func_s g_ecall_func_tbl[MAX_MSPT_ECALL_FUNC_NUM];
static struct msp_chan_cb_s g_msp_chan_cb_tbl[MAX_MSPT_CB_NUM];

/*
 * @brief      : common_test_process  common process
 * @param[in]  : file input pointer, cmd param struct input
 * @return     : MSP_TA_CHANNEL_OK is success, OTHER is failed
 * @note       : support file input
 */
static uint32_t common_test_process(char *iodata, const struct msp_chan_parms *chan_parms)
{
    uint32_t ret = MSP_CHAN_CPROC_CMD_ERROR;
    char *pfunc_name = NULL;
    uint32_t i;

    if (chan_parms == NULL || chan_parms->parm_info[0] > PARMNUM)
        return MSP_CHAN_PARM_ERROR;

    pfunc_name = (char *)&(chan_parms->parm[0]);

    (void)pthread_mutex_lock(&g_msp_chan_mutex);
    if (g_mspt_cproc_cur_num > MAX_MSPT_COMMON_PROC_NUM) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: cproc table err, cmd:%s fail\n", pfunc_name);
        return MSP_CHAN_REGISTRY_ERROR;
    }

    for (i = 0; i < g_mspt_cproc_cur_num; i++) {
        if (g_common_test_func_tbl[i].proc_func == NULL)
            continue;

        if (strncmp(g_common_test_func_tbl[i].cproc_name, pfunc_name,
            strlen(g_common_test_func_tbl[i].cproc_name) + 1) == 0) {
            (void)pthread_mutex_unlock(&g_msp_chan_mutex);
            ret = g_common_test_func_tbl[i].proc_func(chan_parms, iodata);
            return ret;
        }
    }
    (void)pthread_mutex_unlock(&g_msp_chan_mutex);
    tloge("msp_chan: common process not found.\n");

    return ret;
}

/*
 * @brief      : ecall_func_process  ecall process
 * @param[in]  : file input pointer, cmd param struct input
 * @return     : MSP_TA_CHANNEL_OK is success, OTHER is failed
 * @note       : can not support file input
 */
static uint32_t ecall_func_process(char *iodata, const struct msp_chan_parms *chan_parms)
{
    uint32_t ret = MSP_CHAN_ECALL_CMD_ERROR;
    char *efunc_name = NULL;
    uint32_t i;
    (void)iodata;

    if (chan_parms == NULL || chan_parms->parm_info[0] > PARMNUM)
        return MSP_CHAN_PARM_ERROR;

    efunc_name = (char *)&(chan_parms->parm[0]);

    (void)pthread_mutex_lock(&g_msp_chan_mutex);
    if (g_mspt_efunc_cur_num > MAX_MSPT_ECALL_FUNC_NUM) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: efunc table err, cmd:%s fail\n", efunc_name);
        return MSP_CHAN_REGISTRY_ERROR;
    }

    for (i = 0; i < g_mspt_efunc_cur_num; i++) {
        if (g_ecall_func_tbl[i].ecall_func == NULL)
            continue;

        if (strncmp(g_ecall_func_tbl[i].efunc_name, efunc_name,
            strlen(g_ecall_func_tbl[i].efunc_name) + 1) == 0) {
            (void)pthread_mutex_unlock(&g_msp_chan_mutex);
            ret = g_ecall_func_tbl[i].ecall_func(chan_parms);
            return ret;
        }
    }
    (void)pthread_mutex_unlock(&g_msp_chan_mutex);
    tloge("msp_chan: ecall cmd not found.\n");

    return ret;
}

/*
 * @brief      : register msp channel common test process
 * @param[in]  : command char*, common test process
 * @return     : MSP_TA_CHANNEL_OK is success, OTHER is failed
 * @note       : support file input
 */
uint32_t msp_chan_rgst_cproc_func(const char *desc,
                                  uint32_t (*cproc_func)(const struct msp_chan_parms *chan_parms, char *iodata))
{
    uint32_t i;

    if (desc == NULL || strlen(desc) >= MAX_MSPT_FUNC_CHAR_SIZE)
        return MSP_CHAN_CPROC_CMD_ERROR;

    (void)pthread_mutex_lock(&g_msp_chan_mutex);
    if (g_mspt_cproc_cur_num >= MAX_MSPT_COMMON_PROC_NUM) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: cproc full, rgst:%s fail\n", desc);
        return MSP_CHAN_REGISTRY_ERROR;
    }

    for (i = 0; i < g_mspt_cproc_cur_num; i++) {
        if (strncmp(g_common_test_func_tbl[i].cproc_name, desc,
            strlen(g_common_test_func_tbl[i].cproc_name) + 1) == 0) {
            (void)pthread_mutex_unlock(&g_msp_chan_mutex);
            tloge("msp_chan: rgst cproc repeate:%s\n", desc);
            return MSP_CHAN_CPROC_CMD_ERROR;
        }
    }

    if (memcpy_s(g_common_test_func_tbl[g_mspt_cproc_cur_num].cproc_name, MAX_MSPT_FUNC_CHAR_SIZE,
        desc, strlen(desc) + 1) != EOK) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: rgst cproc:%s fail\n", desc);
        return MSP_CHAN_OVERFLOW_ERROR;
    }
    g_common_test_func_tbl[g_mspt_cproc_cur_num].proc_func = cproc_func;
    g_mspt_cproc_cur_num++;
    (void)pthread_mutex_unlock(&g_msp_chan_mutex);

    return MSP_TA_CHANNEL_OK;
}

/*
 * @brief      : register msp channel ecall function
 * @param[in]  : command char*, ecall function
 * @return     : MSP_TA_CHANNEL_OK is success, OTHER is failed
 * @note       : can not support file input
 */
uint32_t msp_chan_rgst_ecall_func(const char *desc,
                                  uint32_t (*ecall_func)(const struct msp_chan_parms *chan_parms))
{
    uint32_t i;

    if (desc == NULL || strlen(desc) >= MAX_MSPT_FUNC_CHAR_SIZE)
        return MSP_CHAN_ECALL_CMD_ERROR;

    (void)pthread_mutex_lock(&g_msp_chan_mutex);
    if (g_mspt_efunc_cur_num >= MAX_MSPT_ECALL_FUNC_NUM) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: efunc full, rgst:%s fail\n", desc);
        return MSP_CHAN_REGISTRY_ERROR;
    }

    for (i = 0; i < g_mspt_efunc_cur_num; i++) {
        if (strncmp(g_ecall_func_tbl[i].efunc_name, desc,
            strlen(g_ecall_func_tbl[i].efunc_name) + 1) == 0) {
            (void)pthread_mutex_unlock(&g_msp_chan_mutex);
            tloge("msp_chan: rgst ecall repeate:%s\n", desc);
            return MSP_CHAN_ECALL_CMD_ERROR;
        }
    }

    if (memcpy_s(g_ecall_func_tbl[g_mspt_efunc_cur_num].efunc_name, MAX_MSPT_FUNC_CHAR_SIZE,
        desc, strlen(desc) + 1) != EOK) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: rgst ecall:%s fail\n", desc);
        return MSP_CHAN_OVERFLOW_ERROR;
    }
    g_ecall_func_tbl[g_mspt_efunc_cur_num].ecall_func = ecall_func;
    g_mspt_efunc_cur_num++;
    (void)pthread_mutex_unlock(&g_msp_chan_mutex);

    return MSP_TA_CHANNEL_OK;
}


/*
 * @brief      : msp_cmd_analysis_moudle  cmd analysis
 * @param[in]  : cmd, input pointer, max data len, msp_chan_parms pointer
 * @return     : 0：success，!0：fail
 */
static uint32_t msp_cmd_analysis_moudle(uint32_t cmd, char *input,
                                        uint32_t max_data_len, const struct msp_chan_parms *parms)
{
    (void)max_data_len;
    uint32_t i;
    uint32_t ret = MSP_CHAN_CMD_ERROR;

    (void)pthread_mutex_lock(&g_msp_chan_mutex);
    if (g_mspt_cb_cur_num > MAX_MSPT_CB_NUM) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: cmd table err, cmd:0x%x fail\n", cmd);
        return MSP_CHAN_REGISTRY_ERROR;
    }

    for (i = 0; i < g_mspt_cb_cur_num; i++) {
        if (g_msp_chan_cb_tbl[i].cmd == cmd && g_msp_chan_cb_tbl[i].cb_func != NULL) {
            (void)pthread_mutex_unlock(&g_msp_chan_mutex);
            ret = g_msp_chan_cb_tbl[i].cb_func(input, parms);
            return ret;
        }
    }

    (void)pthread_mutex_unlock(&g_msp_chan_mutex);
    tloge("msp_chan: Invalid cmd:0x%x\n", cmd);

    return ret;
}

/*
 * @brief      : register msp channel callback function
 * @param[in]  : cmd, callback function
 * @return     : MSP_TA_CHANNEL_OK：success，others：fail
 */
uint32_t msp_chan_rgst_callback(uint32_t cmd,
                                uint32_t (*cb_func)(char *iodata, const struct msp_chan_parms *chan_parms))
{
    uint32_t i;

    (void)pthread_mutex_lock(&g_msp_chan_mutex);
    if (g_mspt_cb_cur_num >= MAX_MSPT_CB_NUM) {
        (void)pthread_mutex_unlock(&g_msp_chan_mutex);
        tloge("msp_chan: rgst cmd:0x%x fail\n", cmd);
        return MSP_CHAN_REGISTRY_ERROR;
    }

    for (i = 0; i < g_mspt_cb_cur_num; i++) {
        if (g_msp_chan_cb_tbl[i].cmd == cmd) {
            (void)pthread_mutex_unlock(&g_msp_chan_mutex);
            tloge("msp_chan: rgst callback repeate:0x%x\n", cmd);
            return MSP_CHAN_CMD_ERROR;
        }
    }

    g_msp_chan_cb_tbl[g_mspt_cb_cur_num].cmd = cmd;
    g_msp_chan_cb_tbl[g_mspt_cb_cur_num].cb_func = cb_func;
    g_mspt_cb_cur_num++;
    (void)pthread_mutex_unlock(&g_msp_chan_mutex);

    return MSP_TA_CHANNEL_OK;
}

/*
 * @brief      : tee_call_msp_drivers  ta-->teeos entry function
 * @param[in]  : cmd, iodata, max data len, parm pointer, param size
 * @return     : 0：success，!0：fail
 */
static uint32_t tee_call_msp_drivers(uint32_t cmd, char *iodata,
                                     uint32_t max_data_len, const char *parm_info, uint32_t parm_size)
{
    uint32_t ret;
    struct msp_chan_parms *pparm_info = NULL;

    pparm_info = (struct msp_chan_parms*)parm_info;
    if (iodata == NULL || pparm_info == NULL ||
        (parm_size != sizeof(struct msp_chan_parms))) {
        ret = MSP_CHAN_DATA_ERROR;
        tloge("msp_chan: parm error.\n");
        return ret;
    }

    ret = msp_cmd_analysis_moudle(cmd, iodata, max_data_len, pparm_info);
    if (ret != MSP_TA_CHANNEL_OK)
        tloge("msp_chan: cmd_analysis_moudle ret = 0x%x!\n", ret);

    return ret;
}

/*
 * @brief      : register common test process and channel test process
 * @param[in]  : NA
 * @return     : MSP_TA_CHANNEL_OK：success，others：fail
 */
static int32_t msp_chan_init(void)
{
    uint32_t ret;

    ret = msp_chan_rgst_callback(HIEPS_ECALL, ecall_func_process);
    if (ret != MSP_TA_CHANNEL_OK)
        return ret;

    ret = msp_chan_rgst_callback(COMMON_TEST, common_test_process);
    if (ret != MSP_TA_CHANNEL_OK)
        return ret;

    return MSP_TA_CHANNEL_OK;
}

/*
 * @brief      : msp_chan_syscall : support syscall for msp channel.
 * @param[in]  : swi_id: module id.
 * @param[in]  : params : parameter registers.
 * @param[in]  : permissions: access permission.
 * @return     : 0: successful, -1: failed.
 */
int32_t msp_chan_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t uwRet = 0;
    const uint32_t DATA_OFFSET = 1;
    const uint32_t DATA_LEN_OFFSET = 2;
    const uint32_t PARAM_OFFSET = 3;
    const uint32_t PARAM_SIZE_OFFSET = 4;
    const int32_t CHAN_SYSCALL_FAIL = -1;

    if (params == NULL || params->args == 0) {
        tloge("%s invalid input\n", __func__);
        return CHAN_SYSCALL_FAIL;
    }
    /* According to ARM AAPCS arguments from 5-> in a function call
     * are stored on the stack, which in this case is pointer by
     * user sp. Our own TrustedCore also push FP and LR on the stack
     * just before SWI, so skip them
     */
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_MSP_CHAN_CDRM, permissions, MSP_CHAN_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[DATA_OFFSET], args[DATA_LEN_OFFSET]);
        if (args[PARAM_SIZE_OFFSET] > 0) {
            ACCESS_CHECK_A64(args[PARAM_OFFSET], args[PARAM_SIZE_OFFSET]);
        } else {
            tloge("msp_chan:syscall err!\n");
            return CHAN_SYSCALL_FAIL;
        }
        ACCESS_READ_RIGHT_CHECK(args[DATA_OFFSET], args[DATA_LEN_OFFSET]);
        ACCESS_WRITE_RIGHT_CHECK(args[DATA_OFFSET], args[DATA_LEN_OFFSET]);
        ACCESS_READ_RIGHT_CHECK(args[PARAM_OFFSET], args[PARAM_SIZE_OFFSET]);
        ACCESS_WRITE_RIGHT_CHECK(args[PARAM_OFFSET], args[PARAM_SIZE_OFFSET]);

        uwRet = tee_call_msp_drivers((uint32_t)args[0],
                                     (char *)(uintptr_t)args[DATA_OFFSET],
                                     (uint32_t)args[DATA_LEN_OFFSET],
                                     (const char *)(uintptr_t)args[PARAM_OFFSET],
                                     (uint32_t)args[PARAM_SIZE_OFFSET]);
        args[0] = uwRet;
        SYSCALL_END

        default:
            return CHAN_SYSCALL_FAIL;
    }
    return 0;
}

#ifdef CONFIG_FEATURE_SEPLAT
/* declare msp ta channel module */
DECLARE_TC_DRV_MULTI(
    msp_ta_channel,     /* name */
    0,                  /* reserved1 */
    0,                  /* reserved2 */
    0,                  /* reserved3 */
    TC_DRV_MODULE_INIT, /* priority */
    msp_chan_init,      /* init */
    NULL,               /* handle */
    msp_chan_syscall,   /* syscall */
    NULL,               /* suspend */
    NULL                /* resume */
);
#else
/* declare msp ta channel module */
DECLARE_TC_DRV(
    msp_ta_channel,     /* name */
    0,                  /* reserved1 */
    0,                  /* reserved2 */
    0,                  /* reserved3 */
    TC_DRV_MODULE_INIT, /* priority */
    msp_chan_init,      /* init */
    NULL,               /* handle */
    msp_chan_syscall,   /* syscall */
    NULL,               /* suspend */
    NULL                /* resume */
);
#endif